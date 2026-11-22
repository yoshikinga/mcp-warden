import {
  AuditLogger,
  RingBufferAuditSink,
  type RecordAuditParams
} from "./audit/audit-logger.js";
import { verifyAuditChain } from "./audit/hash-chain.js";
import {
  HmacAuditSigner,
  isSignedAuditEntry,
  verifySignedAuditChain,
  type SignedAuditEntry
} from "./audit/hmac-signer.js";
import { serializeAuditEntriesToNdjson } from "./audit/ndjson-codec.js";
import { WardenError } from "./errors/warden-error.js";
import { SessionCircuitBreaker } from "./guards/circuit-breaker.js";
import { CommandInjectionGuard } from "./guards/command-injection-guard.js";
import { EgressSecretGuard } from "./guards/egress-secret-guard.js";
import { PathTraversalGuard } from "./guards/path-traversal-guard.js";
import { PayloadGuard } from "./guards/payload-guard.js";
import { SlidingWindowRateLimiter } from "./guards/rate-limiter.js";
import { SsrfGuard } from "./guards/ssrf-guard.js";
import { ToolIntegrityGuard } from "./guards/tool-integrity-guard.js";
import { UnicodeTrojanGuard } from "./guards/unicode-trojan-guard.js";
import { PolicyEngine } from "./policy/policy-engine.js";
import { validateAndNormalizeEnvelope } from "./protocol/envelope-validator.js";
import {
  TelemetryManager,
  type ViolationHookErrorHandler
} from "./telemetry/violation-hooks.js";
import type {
  AuditEntry,
  AuditReasonCode,
  AuditSink,
  ChainVerificationReport
} from "./types/audit.js";
import type { JsonRpcErrorResponse, JsonRpcId } from "./types/jsonrpc.js";
import type { ExecutionContext, NormalizedMcpInvocation } from "./types/mcp.js";
import type {
  CircuitBreakerSnapshot,
  EgressInspectionResult,
  EnforcementMode,
  McpToolDefinition,
  ToolIntegrityCheckResult,
  V11ReasonCode,
  ViolationHook,
  WardenMetricsSnapshot,
  WardenV11Config
} from "./types/v1-1.js";

/**
 * Runtime options for customizing audit sinks, violation hooks, and deterministic clocks in McpWarden.
 */
export interface McpWardenRuntimeOptions {
  /** Additional external audit sinks (e.g., NdjsonAuditSink, SIEM shipper) */
  readonly auditSinks?: readonly AuditSink[];
  /** Maximum records kept in the built-in memory ring buffer (default: 1000) */
  readonly maxMemoryAuditEntries?: number;
  /** Optional real-time callbacks invoked on policy or threat violations */
  readonly violationHooks?: readonly ViolationHook[];
  /** Optional observer invoked if a user-supplied violationHook throws */
  readonly onHookError?: ViolationHookErrorHandler;
  /** Optional clock provider used for deterministic testing */
  readonly nowFn?: () => number;
}

/**
 * Complete outcome returned by `McpWarden.inspect()`.
 */
export interface InspectionResult {
  readonly allowed: boolean;
  readonly mode: EnforcementMode;
  /** True when a rule or guard triggered (even if allowed through under DRY_RUN mode) */
  readonly wouldDeny: boolean;
  /** Granular v1.1 threat classification when triggered by a v1.1 guard */
  readonly v11ReasonCode: V11ReasonCode | null;
  /** Hex HMAC-SHA256 signature when `hmacAudit` is configured, otherwise null */
  readonly hmacSignature: string | null;
  readonly invocation: NormalizedMcpInvocation | null;
  readonly auditEntry: AuditEntry | SignedAuditEntry;
  readonly error: WardenError | null;
}

interface PendingDryRunViolation {
  readonly reasonCode: AuditReasonCode;
  readonly v11ReasonCode: V11ReasonCode | null;
  readonly matchedRuleId: string | null;
  readonly detail: string;
  readonly isCircuitBreaker: boolean;
}

function tryExtractBestEffortRequestId(rawInput: unknown): JsonRpcId {
  if (typeof rawInput === "object" && rawInput !== null && !Array.isArray(rawInput)) {
    const candidate = (rawInput as Record<string, unknown>)["id"];
    if (
      typeof candidate === "string" ||
      (typeof candidate === "number" && Number.isFinite(candidate)) ||
      candidate === null
    ) {
      return candidate;
    }
  }
  return null;
}

function resolveSessionBreakerKey(context: ExecutionContext): string {
  return context.sessionId !== undefined && context.sessionId.length > 0
    ? context.sessionId
    : context.principalId;
}

/**
 * Full-Duplex Zero-Dependency Security Firewall, Zero-Trust RBAC Engine,
 * Egress Secret Scrubber, and SHA-256 / HMAC-SHA256 Audit Gateway for MCP servers.
 */
export class McpWarden {
  private readonly config: WardenV11Config;
  private mode: EnforcementMode;
  private readonly allowDiscoveryMethods: boolean;
  private readonly maxDecodePasses: number;
  private readonly circuitBreaker: SessionCircuitBreaker | null;
  private readonly payloadGuard: PayloadGuard;
  private readonly unicodeGuard: UnicodeTrojanGuard;
  private readonly pathGuard: PathTraversalGuard | null;
  private readonly commandGuard: CommandInjectionGuard;
  private readonly ssrfGuard: SsrfGuard;
  private readonly rateLimiter: SlidingWindowRateLimiter;
  private readonly policyEngine: PolicyEngine;
  private readonly toolIntegrityGuard: ToolIntegrityGuard;
  private readonly egressGuard: EgressSecretGuard;
  private readonly autoInspectWrappedEgress: boolean;
  private readonly hmacSigner: HmacAuditSigner | null;
  private readonly memoryAuditSink: RingBufferAuditSink;
  private readonly externalAuditSinks: readonly AuditSink[];
  private readonly finalizedBySequence = new Map<
    number,
    AuditEntry | SignedAuditEntry
  >();
  private readonly auditLogger: AuditLogger;
  private readonly telemetry: TelemetryManager;

  public constructor(
    config: WardenV11Config,
    runtimeOptions: McpWardenRuntimeOptions = {}
  ) {
    this.config = config;
    this.mode = config.mode ?? "ENFORCE";
    this.allowDiscoveryMethods = config.allowDiscoveryMethods ?? true;
    this.maxDecodePasses = config.maxDecodePasses ?? 3;

    const nowFn = runtimeOptions.nowFn ?? (() => Date.now());

    this.circuitBreaker =
      config.circuitBreaker !== undefined
        ? new SessionCircuitBreaker(config.circuitBreaker, nowFn)
        : null;
    this.payloadGuard = new PayloadGuard(config.payload);
    this.unicodeGuard = new UnicodeTrojanGuard(config.unicode);
    this.pathGuard =
      config.path !== undefined ? new PathTraversalGuard(config.path) : null;
    this.commandGuard = new CommandInjectionGuard(config.command);
    this.ssrfGuard = new SsrfGuard(config.ssrf);
    this.rateLimiter = new SlidingWindowRateLimiter(config.rateLimit, nowFn);
    this.policyEngine = new PolicyEngine(config.rules);
    this.toolIntegrityGuard = new ToolIntegrityGuard(config.toolIntegrity);
    this.egressGuard = new EgressSecretGuard(config.egress);
    this.autoInspectWrappedEgress =
      config.egress !== undefined && (config.egress.enabled ?? true);

    this.hmacSigner =
      config.hmacAudit !== undefined
        ? new HmacAuditSigner(config.hmacAudit)
        : null;

    this.memoryAuditSink = new RingBufferAuditSink(
      runtimeOptions.maxMemoryAuditEntries ?? 1_000
    );
    this.externalAuditSinks = [...(runtimeOptions.auditSinks ?? [])];

    const orchestratingSink: AuditSink = {
      write: async (sealedEntry: AuditEntry): Promise<void> => {
        const finalEntry: AuditEntry | SignedAuditEntry =
          this.hmacSigner !== null
            ? await this.hmacSigner.signEntry(sealedEntry)
            : sealedEntry;

        this.finalizedBySequence.set(sealedEntry.sequence, finalEntry);
        this.memoryAuditSink.write(finalEntry);

        for (let i = 0; i < this.externalAuditSinks.length; i += 1) {
          const extSink = this.externalAuditSinks[i];
          if (extSink !== undefined) {
            await extSink.write(finalEntry);
          }
        }
      }
    };

    this.auditLogger = new AuditLogger({
      sinks: [orchestratingSink],
      ...(config.sensitiveAuditKeys !== undefined
        ? { sensitiveKeys: config.sensitiveAuditKeys }
        : {}),
      nowFn
    });

    this.telemetry = new TelemetryManager({
      ...(runtimeOptions.violationHooks !== undefined
        ? { hooks: runtimeOptions.violationHooks }
        : {}),
      ...(runtimeOptions.onHookError !== undefined
        ? { onHookError: runtimeOptions.onHookError }
        : {})
    });
  }

  public getMode(): EnforcementMode {
    return this.mode;
  }

  public setMode(mode: EnforcementMode): void {
    this.mode = mode;
  }

  public onViolation(hook: ViolationHook): () => void {
    return this.telemetry.addHook(hook);
  }

  public getMetrics(): WardenMetricsSnapshot {
    return this.telemetry.getSnapshot();
  }

  public resetMetrics(): void {
    this.telemetry.resetMetrics();
  }

  public getCircuitBreakerSnapshot(
    sessionOrPrincipalKey: string
  ): CircuitBreakerSnapshot {
    if (this.circuitBreaker === null) {
      return {
        key: sessionOrPrincipalKey,
        state: "CLOSED",
        recentViolations: 0,
        openedAtMs: null,
        remainingCooldownMs: 0
      };
    }
    return this.circuitBreaker.getSnapshot(sessionOrPrincipalKey);
  }

  /**
   * Executes the inline ingress security pipeline against a raw JSON-RPC string or object.
   */
  public async inspect(
    rawRequest: unknown,
    context: ExecutionContext
  ): Promise<InspectionResult> {
    const startTime = performance.now();
    const activeMode = this.mode;
    const breakerKey = resolveSessionBreakerKey(context);
    let pendingDryRun: PendingDryRunViolation | null = null;

    // Stage 0: Behavioral Session Circuit Breaker
    if (this.circuitBreaker !== null) {
      const cbCheck = this.circuitBreaker.checkBeforeRequest(breakerKey);
      if (!cbCheck.allowed) {
        if (activeMode === "ENFORCE") {
          const requestId = tryExtractBestEffortRequestId(rawRequest);
          return this.finalizeViolation({
            startTime,
            activeMode,
            allowDryRunBypass: false,
            isCircuitBreaker: true,
            requestId,
            context,
            method: "unknown",
            operationKind: "unknown",
            target: "session-quarantine",
            invocation: null,
            reasonCode: "RATE_LIMIT_EXCEEDED",
            v11ReasonCode: "CIRCUIT_BREAKER_OPEN",
            matchedRuleId: null,
            detail: cbCheck.detail,
            argumentsToLog: {}
          });
        }
        pendingDryRun = {
          reasonCode: "RATE_LIMIT_EXCEEDED",
          v11ReasonCode: "CIRCUIT_BREAKER_OPEN",
          matchedRuleId: null,
          detail: cbCheck.detail,
          isCircuitBreaker: true
        };
      }
    }

    // Stage 1: DoS & Structural Payload Guard
    const payloadCheck = this.payloadGuard.check(rawRequest);
    if (!payloadCheck.allowed) {
      if (activeMode === "ENFORCE") {
        this.circuitBreaker?.recordOutcome(breakerKey, false);
        const requestId = tryExtractBestEffortRequestId(rawRequest);
        return this.finalizeViolation({
          startTime,
          activeMode,
          allowDryRunBypass: false,
          isCircuitBreaker: false,
          requestId,
          context,
          method: "unknown",
          operationKind: "unknown",
          target: "unknown",
          invocation: null,
          reasonCode: payloadCheck.reasonCode,
          v11ReasonCode: null,
          matchedRuleId: null,
          detail: payloadCheck.detail,
          argumentsToLog: {}
        });
      }
      if (pendingDryRun === null) {
        pendingDryRun = {
          reasonCode: payloadCheck.reasonCode,
          v11ReasonCode: null,
          matchedRuleId: null,
          detail: payloadCheck.detail,
          isCircuitBreaker: false
        };
      }
    }

    // Stage 2: JSON-RPC 2.0 Envelope Validation & Multi-Pass Canonicalization
    const envelopeCheck = validateAndNormalizeEnvelope(rawRequest, {
      rejectBatchRequests: this.config.payload?.rejectBatchRequests ?? true,
      maxDecodePasses: this.maxDecodePasses
    });

    if (!envelopeCheck.ok) {
      this.circuitBreaker?.recordOutcome(breakerKey, false);
      return this.finalizeViolation({
        startTime,
        activeMode,
        allowDryRunBypass: false,
        isCircuitBreaker: false,
        requestId: envelopeCheck.requestId,
        context,
        method: envelopeCheck.method,
        operationKind: envelopeCheck.operationKind,
        target: envelopeCheck.target,
        invocation: null,
        reasonCode: envelopeCheck.reasonCode,
        v11ReasonCode: null,
        matchedRuleId: null,
        detail: envelopeCheck.detail,
        argumentsToLog: {}
      });
    }

    const { invocation } = envelopeCheck;

    if (pendingDryRun !== null) {
      if (!pendingDryRun.isCircuitBreaker) {
        this.circuitBreaker?.recordOutcome(breakerKey, false);
      }
      return this.finalizeViolation({
        startTime,
        activeMode,
        allowDryRunBypass: true,
        isCircuitBreaker: pendingDryRun.isCircuitBreaker,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: pendingDryRun.reasonCode,
        v11ReasonCode: pendingDryRun.v11ReasonCode,
        matchedRuleId: pendingDryRun.matchedRuleId,
        detail: pendingDryRun.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    // Stage 2.5: Unicode Trojan & Plane 14 Tag Smuggling Guard
    const unicodeCheck = this.unicodeGuard.check(invocation);
    if (!unicodeCheck.allowed) {
      this.circuitBreaker?.recordOutcome(breakerKey, false);
      return this.finalizeViolation({
        startTime,
        activeMode,
        allowDryRunBypass: true,
        isCircuitBreaker: false,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: "EVASION_DETECTED",
        v11ReasonCode: "UNICODE_TROJAN_DETECTED",
        matchedRuleId: null,
        detail: unicodeCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    // Stage 3: Bounded-Memory Sliding-Window Rate Limiter
    const rateCheck = this.rateLimiter.check(
      context.principalId,
      invocation.target
    );
    if (!rateCheck.allowed) {
      this.circuitBreaker?.recordOutcome(breakerKey, false);
      return this.finalizeViolation({
        startTime,
        activeMode,
        allowDryRunBypass: true,
        isCircuitBreaker: false,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: rateCheck.reasonCode,
        v11ReasonCode: null,
        matchedRuleId: null,
        detail: rateCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    // Stage 4: Zero-Trust RBAC Policy Engine
    const policyDecision = this.policyEngine.evaluate(invocation, context);
    let allowReasonCode: Extract<
      AuditReasonCode,
      "ALLOWED_BY_POLICY" | "ALLOWED_DISCOVERY"
    > = "ALLOWED_BY_POLICY";
    let matchedRuleId: string | null = policyDecision.matchedRuleId;
    let allowDetail = policyDecision.reason;

    if (!policyDecision.allowed) {
      const canPermitLifecycleDiscovery =
        policyDecision.reasonCode === "POLICY_NO_MATCH_FAIL_CLOSED" &&
        invocation.operationKind === "lifecycle" &&
        this.allowDiscoveryMethods;

      if (canPermitLifecycleDiscovery) {
        allowReasonCode = "ALLOWED_DISCOVERY";
        matchedRuleId = null;
        allowDetail = `Allowed standard MCP lifecycle method '${invocation.method}'.`;
      } else {
        this.circuitBreaker?.recordOutcome(breakerKey, false);
        return this.finalizeViolation({
          startTime,
          activeMode,
          allowDryRunBypass: true,
          isCircuitBreaker: false,
          requestId: invocation.requestId,
          context,
          method: invocation.method,
          operationKind: invocation.operationKind,
          target: invocation.target,
          invocation,
          reasonCode: policyDecision.reasonCode,
          v11ReasonCode: null,
          matchedRuleId: policyDecision.matchedRuleId,
          detail: policyDecision.reason,
          argumentsToLog: invocation.canonicalArguments
        });
      }
    }

    // Stage 5: Deep Content Threat Guards (Path Traversal -> Command Injection -> SSRF)
    if (this.pathGuard !== null) {
      const pathCheck = this.pathGuard.check(invocation);
      if (!pathCheck.allowed) {
        this.circuitBreaker?.recordOutcome(breakerKey, false);
        return this.finalizeViolation({
          startTime,
          activeMode,
          allowDryRunBypass: true,
          isCircuitBreaker: false,
          requestId: invocation.requestId,
          context,
          method: invocation.method,
          operationKind: invocation.operationKind,
          target: invocation.target,
          invocation,
          reasonCode: pathCheck.reasonCode,
          v11ReasonCode: null,
          matchedRuleId,
          detail: pathCheck.detail,
          argumentsToLog: invocation.canonicalArguments
        });
      }
    }

    const commandCheck = this.commandGuard.check(invocation);
    if (!commandCheck.allowed) {
      this.circuitBreaker?.recordOutcome(breakerKey, false);
      return this.finalizeViolation({
        startTime,
        activeMode,
        allowDryRunBypass: true,
        isCircuitBreaker: false,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: commandCheck.reasonCode,
        v11ReasonCode: null,
        matchedRuleId,
        detail: commandCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    const ssrfCheck = this.ssrfGuard.check(invocation);
    if (!ssrfCheck.allowed) {
      this.circuitBreaker?.recordOutcome(breakerKey, false);
      return this.finalizeViolation({
        startTime,
        activeMode,
        allowDryRunBypass: true,
        isCircuitBreaker: false,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: ssrfCheck.reasonCode,
        v11ReasonCode: null,
        matchedRuleId,
        detail: ssrfCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    // Stage 6: Clean Cryptographic SHA-256 (+ HMAC) ALLOW Audit Record
    this.circuitBreaker?.recordOutcome(breakerKey, true);
    this.telemetry.recordAllow();

    const latencyMs = performance.now() - startTime;
    const auditEntry = await this.recordFinalizedAudit({
      requestId: invocation.requestId,
      principalId: context.principalId,
      ...(context.sessionId !== undefined ? { sessionId: context.sessionId } : {}),
      method: invocation.method,
      operationKind: invocation.operationKind,
      target: invocation.target,
      decision: "ALLOW",
      reasonCode: allowReasonCode,
      matchedRuleId,
      detail: allowDetail,
      latencyMs,
      argumentsToLog: invocation.canonicalArguments
    });

    return {
      allowed: true,
      mode: activeMode,
      wouldDeny: false,
      v11ReasonCode: null,
      hmacSignature: isSignedAuditEntry(auditEntry)
        ? auditEntry.hmacSignature
        : null,
      invocation,
      auditEntry,
      error: null
    };
  }

  /**
   * Inspects an upstream MCP `tools/list` catalog for Tool Poisoning and mid-session Rug-Pulls,
   * recording cryptographic audit evidence and firing violation hooks on tampering.
   */
  public async inspectToolsList(
    serverId: string,
    tools: readonly McpToolDefinition[],
    context: ExecutionContext = { principalId: "mcp-host", roles: ["system"] }
  ): Promise<ToolIntegrityCheckResult> {
    const startTime = performance.now();
    const activeMode = this.mode;
    const check = await this.toolIntegrityGuard.inspectToolsList(serverId, tools);
    const latencyMs = performance.now() - startTime;

    if (check.allowed) {
      this.telemetry.recordAllow();
      await this.recordFinalizedAudit({
        requestId: null,
        principalId: context.principalId,
        ...(context.sessionId !== undefined ? { sessionId: context.sessionId } : {}),
        method: "tools/list",
        operationKind: "lifecycle",
        target: serverId,
        decision: "ALLOW",
        reasonCode: "ALLOWED_DISCOVERY",
        matchedRuleId: null,
        detail: check.newlyPinned
          ? `Pinned SHA-256 catalog for '${serverId}' (${tools.length} tools).`
          : `Verified SHA-256 catalog integrity for '${serverId}'.`,
        latencyMs,
        argumentsToLog: { toolCount: tools.length }
      });
      return check;
    }

    const blocked = activeMode === "ENFORCE";
    const auditEntry = await this.recordFinalizedAudit({
      requestId: null,
      principalId: context.principalId,
      ...(context.sessionId !== undefined ? { sessionId: context.sessionId } : {}),
      method: "tools/list",
      operationKind: "lifecycle",
      target: `${serverId}/${check.violatingToolName}`,
      decision: "DENY",
      reasonCode: "EVASION_DETECTED",
      matchedRuleId: null,
      detail: blocked
        ? `[${check.reasonCode}] ${check.detail}`
        : `[DRY_RUN WOULD_DENY] [${check.reasonCode}] ${check.detail}`,
      latencyMs,
      argumentsToLog: {
        serverId,
        violatingToolName: check.violatingToolName
      }
    });

    this.telemetry.recordViolation({
      reasonCode: check.reasonCode,
      blocked,
      isDryRunWouldDeny: !blocked
    });

    await this.telemetry.dispatchViolation({
      timestamp: auditEntry.timestamp,
      mode: activeMode,
      blocked,
      requestId: null,
      principalId: context.principalId,
      sessionId: context.sessionId ?? null,
      operationKind: "lifecycle",
      target: `${serverId}/${check.violatingToolName}`,
      reasonCode: check.reasonCode,
      auditEntry
    });

    if (!blocked) {
      return {
        allowed: true,
        serverId,
        newlyPinned: false,
        fingerprints: check.fingerprints
      };
    }

    return check;
  }

  /**
   * Inspects an outbound MCP tool/resource response payload to scrub or block leaked credentials
   * before they enter the AI Agent's context window.
   */
  public async inspectResponse<TPayload = unknown>(
    responsePayload: TPayload,
    context: ExecutionContext,
    target: string = "mcp:response",
    requestId: JsonRpcId = null
  ): Promise<EgressInspectionResult<TPayload>> {
    const startTime = performance.now();
    const activeMode = this.mode;
    const outcome = this.egressGuard.inspect(responsePayload);

    if (outcome.findings.length === 0 || outcome.reasonCode === null) {
      return outcome;
    }

    const latencyMs = performance.now() - startTime;
    const isBlockedInEnforce = !outcome.allowed && activeMode === "ENFORCE";
    const auditEntry = await this.recordFinalizedAudit({
      requestId,
      principalId: context.principalId,
      ...(context.sessionId !== undefined ? { sessionId: context.sessionId } : {}),
      method: "mcp/egress",
      operationKind: "tool",
      target,
      decision: outcome.allowed ? "ALLOW" : "DENY",
      reasonCode: outcome.allowed ? "ALLOWED_BY_POLICY" : "SENSITIVE_FILE_BLOCKED",
      matchedRuleId: null,
      detail:
        !outcome.allowed && activeMode === "DRY_RUN"
          ? `[DRY_RUN WOULD_DENY] [${outcome.reasonCode}] ${outcome.detail}`
          : `[${outcome.reasonCode}] ${outcome.detail}`,
      latencyMs,
      argumentsToLog: {
        findingCount: outcome.findings.length,
        kinds: outcome.findings.map((f) => f.kind)
      }
    });

    this.telemetry.recordEgressScrubbed(outcome.reasonCode);

    await this.telemetry.dispatchViolation({
      timestamp: auditEntry.timestamp,
      mode: activeMode,
      blocked: isBlockedInEnforce,
      requestId,
      principalId: context.principalId,
      sessionId: context.sessionId ?? null,
      operationKind: "tool",
      target,
      reasonCode: outcome.reasonCode,
      auditEntry
    });

    if (!outcome.allowed && activeMode === "DRY_RUN") {
      return {
        ...outcome,
        allowed: true,
        sanitizedPayload: responsePayload
      };
    }

    return outcome;
  }

  /**
   * Convenience assertion that returns the validated `NormalizedMcpInvocation`
   * when allowed or throws a typed `WardenError` when blocked.
   */
  public async assertAllowed(
    rawRequest: unknown,
    context: ExecutionContext
  ): Promise<NormalizedMcpInvocation> {
    const result = await this.inspect(rawRequest, context);
    if (!result.allowed || result.invocation === null) {
      throw (
        result.error ??
        new WardenError({
          reasonCode: result.auditEntry.reasonCode,
          internalDetail: result.auditEntry.detail,
          requestId: result.auditEntry.requestId,
          auditHash: result.auditEntry.hash
        })
      );
    }
    return result.invocation;
  }

  /**
   * Wraps an MCP server request handler with full-duplex security enforcement:
   * validates inbound requests AND (when `config.egress` is enabled) scrubs/blocks outbound secrets.
   */
  public wrap<TRequest = unknown, TResponse = unknown>(
    handler: (
      request: TRequest,
      invocation: NormalizedMcpInvocation,
      context: ExecutionContext
    ) => TResponse | Promise<TResponse>,
    resolveContext: (
      request: TRequest
    ) => ExecutionContext | Promise<ExecutionContext>
  ): (request: TRequest) => Promise<TResponse | JsonRpcErrorResponse> {
    return async (request: TRequest): Promise<TResponse | JsonRpcErrorResponse> => {
      const context = await resolveContext(request);
      const inspection = await this.inspect(request, context);
      if (!inspection.allowed || inspection.invocation === null) {
        const err =
          inspection.error ??
          new WardenError({
            reasonCode: inspection.auditEntry.reasonCode,
            internalDetail: inspection.auditEntry.detail,
            requestId: inspection.auditEntry.requestId,
            auditHash: inspection.auditEntry.hash
          });
        return err.toJsonRpcErrorResponse();
      }

      const downstreamResponse = await handler(
        request,
        inspection.invocation,
        context
      );

      if (!this.autoInspectWrappedEgress) {
        return downstreamResponse;
      }

      const egressOutcome = await this.inspectResponse(
        downstreamResponse,
        context,
        inspection.invocation.target,
        inspection.invocation.requestId
      );

      if (!egressOutcome.allowed) {
        const egressErr = new WardenError({
          reasonCode: "SENSITIVE_FILE_BLOCKED",
          internalDetail: egressOutcome.detail,
          requestId: inspection.invocation.requestId,
          auditHash: this.auditLogger.getLastHash()
        });
        return egressErr.toJsonRpcErrorResponse();
      }

      return egressOutcome.sanitizedPayload;
    };
  }

  /**
   * Returns a snapshot of sealed SHA-256 (and optional HMAC-SHA256) audit entries in memory.
   */
  public getAuditEntries(): readonly (AuditEntry | SignedAuditEntry)[] {
    return this.memoryAuditSink.getEntries();
  }

  /**
   * Exports all retained in-memory audit entries as a canonical SIEM-ready NDJSON string.
   */
  public exportAuditNdjson(): string {
    return serializeAuditEntriesToNdjson(this.memoryAuditSink.getEntries());
  }

  /**
   * Cryptographically verifies SHA-256 links (and HMAC-SHA256 tags when `hmacAudit` is active).
   */
  public async verifyAuditTrail(): Promise<ChainVerificationReport> {
    const entries = this.memoryAuditSink.getEntries();
    const allowSubchain = this.memoryAuditSink.hasEvictedEntries();

    if (this.config.hmacAudit !== undefined) {
      return verifySignedAuditChain(entries, this.config.hmacAudit, {
        allowSubchain
      });
    }

    return verifyAuditChain(entries, { allowSubchain });
  }

  /**
   * Resets all in-memory sliding-window rate-limit and session circuit-breaker counters.
   */
  public resetRateLimits(): void {
    this.rateLimiter.reset();
    this.circuitBreaker?.resetAll();
  }

  private async recordFinalizedAudit(
    params: RecordAuditParams
  ): Promise<AuditEntry | SignedAuditEntry> {
    const rawSealed = await this.auditLogger.record(params);
    const finalized = this.finalizedBySequence.get(rawSealed.sequence);
    this.finalizedBySequence.delete(rawSealed.sequence);
    return finalized ?? rawSealed;
  }

  private async finalizeViolation(params: {
    readonly startTime: number;
    readonly activeMode: EnforcementMode;
    readonly allowDryRunBypass: boolean;
    readonly isCircuitBreaker: boolean;
    readonly requestId: JsonRpcId;
    readonly context: ExecutionContext;
    readonly method: string;
    readonly operationKind: NormalizedMcpInvocation["operationKind"];
    readonly target: string;
    readonly invocation: NormalizedMcpInvocation | null;
    readonly reasonCode: AuditReasonCode;
    readonly v11ReasonCode: V11ReasonCode | null;
    readonly matchedRuleId: string | null;
    readonly detail: string;
    readonly argumentsToLog: Readonly<Record<string, unknown>>;
  }): Promise<InspectionResult> {
    const latencyMs = performance.now() - params.startTime;
    const isDryRunBypass =
      params.activeMode === "DRY_RUN" &&
      params.allowDryRunBypass &&
      params.invocation !== null;
    const blocked = !isDryRunBypass;

    const formattedDetail =
      params.v11ReasonCode !== null
        ? `[${params.v11ReasonCode}] ${params.detail}`
        : params.detail;

    const auditEntry = await this.recordFinalizedAudit({
      requestId: params.requestId,
      principalId: params.context.principalId,
      ...(params.context.sessionId !== undefined
        ? { sessionId: params.context.sessionId }
        : {}),
      method: params.method,
      operationKind: params.operationKind,
      target: params.target,
      decision: "DENY",
      reasonCode: params.reasonCode,
      matchedRuleId: params.matchedRuleId,
      detail: isDryRunBypass
        ? `[DRY_RUN WOULD_DENY] ${formattedDetail}`
        : formattedDetail,
      latencyMs,
      argumentsToLog: params.argumentsToLog
    });

    const telemetryReason = params.v11ReasonCode ?? params.reasonCode;
    this.telemetry.recordViolation({
      reasonCode: telemetryReason,
      blocked,
      isDryRunWouldDeny: isDryRunBypass,
      isCircuitBreaker: params.isCircuitBreaker
    });

    await this.telemetry.dispatchViolation({
      timestamp: auditEntry.timestamp,
      mode: params.activeMode,
      blocked,
      requestId: params.requestId,
      principalId: params.context.principalId,
      sessionId: params.context.sessionId ?? null,
      operationKind: params.operationKind,
      target: params.target,
      reasonCode: telemetryReason,
      auditEntry
    });

    const hmacSignature = isSignedAuditEntry(auditEntry)
      ? auditEntry.hmacSignature
      : null;

    if (isDryRunBypass) {
      return {
        allowed: true,
        mode: params.activeMode,
        wouldDeny: true,
        v11ReasonCode: params.v11ReasonCode,
        hmacSignature,
        invocation: params.invocation,
        auditEntry,
        error: null
      };
    }

    const error = new WardenError({
      reasonCode: params.reasonCode,
      internalDetail: formattedDetail,
      requestId: params.requestId,
      auditHash: auditEntry.hash
    });

    return {
      allowed: false,
      mode: params.activeMode,
      wouldDeny: true,
      v11ReasonCode: params.v11ReasonCode,
      hmacSignature,
      invocation: params.invocation,
      auditEntry,
      error
    };
  }
}
