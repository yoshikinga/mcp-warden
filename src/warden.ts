import {
  AuditLogger,
  RingBufferAuditSink
} from "./audit/audit-logger.js";
import { verifyAuditChain } from "./audit/hash-chain.js";
import { WardenError } from "./errors/warden-error.js";
import { CommandInjectionGuard } from "./guards/command-injection-guard.js";
import { PathTraversalGuard } from "./guards/path-traversal-guard.js";
import { PayloadGuard } from "./guards/payload-guard.js";
import { SlidingWindowRateLimiter } from "./guards/rate-limiter.js";
import { SsrfGuard } from "./guards/ssrf-guard.js";
import { PolicyEngine } from "./policy/policy-engine.js";
import { validateAndNormalizeEnvelope } from "./protocol/envelope-validator.js";
import type {
  AuditEntry,
  AuditReasonCode,
  AuditSink,
  ChainVerificationReport
} from "./types/audit.js";
import type { JsonRpcErrorResponse, JsonRpcId } from "./types/jsonrpc.js";
import type { ExecutionContext, NormalizedMcpInvocation } from "./types/mcp.js";
import type { WardenConfig } from "./types/policy.js";

/**
 * Runtime options for customizing audit sinks and deterministic clocks in McpWarden.
 */
export interface McpWardenRuntimeOptions {
  /** Additional external audit sinks (e.g., SIEM shipper, append-only file writer) */
  readonly auditSinks?: readonly AuditSink[];
  /** Maximum records kept in the built-in memory ring buffer (default: 1000) */
  readonly maxMemoryAuditEntries?: number;
  /** Optional clock provider used for deterministic testing */
  readonly nowFn?: () => number;
}

/**
 * Complete outcome returned by `McpWarden.inspect()`.
 */
export interface InspectionResult {
  readonly allowed: boolean;
  readonly invocation: NormalizedMcpInvocation | null;
  readonly auditEntry: AuditEntry;
  readonly error: WardenError | null;
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

/**
 * Inline Zero-Dependency Security Firewall, Zero-Trust RBAC Engine, and
 * Tamper-Evident SHA-256 Audit Gateway for Model Context Protocol (MCP) servers.
 */
export class McpWarden {
  private readonly config: WardenConfig;
  private readonly allowDiscoveryMethods: boolean;
  private readonly maxDecodePasses: number;
  private readonly payloadGuard: PayloadGuard;
  private readonly pathGuard: PathTraversalGuard | null;
  private readonly commandGuard: CommandInjectionGuard;
  private readonly ssrfGuard: SsrfGuard;
  private readonly rateLimiter: SlidingWindowRateLimiter;
  private readonly policyEngine: PolicyEngine;
  private readonly memoryAuditSink: RingBufferAuditSink;
  private readonly auditLogger: AuditLogger;

  public constructor(
    config: WardenConfig,
    runtimeOptions: McpWardenRuntimeOptions = {}
  ) {
    this.config = config;
    this.allowDiscoveryMethods = config.allowDiscoveryMethods ?? true;
    this.maxDecodePasses = config.maxDecodePasses ?? 3;

    const nowFn = runtimeOptions.nowFn ?? (() => Date.now());

    this.payloadGuard = new PayloadGuard(config.payload);
    this.pathGuard =
      config.path !== undefined ? new PathTraversalGuard(config.path) : null;
    this.commandGuard = new CommandInjectionGuard(config.command);
    this.ssrfGuard = new SsrfGuard(config.ssrf);
    this.rateLimiter = new SlidingWindowRateLimiter(config.rateLimit, nowFn);
    this.policyEngine = new PolicyEngine(config.rules);

    this.memoryAuditSink = new RingBufferAuditSink(
      runtimeOptions.maxMemoryAuditEntries ?? 1_000
    );

    const combinedSinks: AuditSink[] = [
      this.memoryAuditSink,
      ...(runtimeOptions.auditSinks ?? [])
    ];

    this.auditLogger = new AuditLogger({
      sinks: combinedSinks,
      ...(config.sensitiveAuditKeys !== undefined
        ? { sensitiveKeys: config.sensitiveAuditKeys }
        : {}),
      nowFn
    });
  }

  /**
   * Executes the full 6-stage inline security pipeline against a raw JSON-RPC string or object:
   * PayloadGuard -> EnvelopeValidator/Canonicalizer -> RateLimiter -> RBAC -> Content Guards -> SHA-256 Audit.
   */
  public async inspect(
    rawRequest: unknown,
    context: ExecutionContext
  ): Promise<InspectionResult> {
    const startTime = performance.now();

    // Stage 1: DoS & Structural Payload Guard
    const payloadCheck = this.payloadGuard.check(rawRequest);
    if (!payloadCheck.allowed) {
      const requestId = tryExtractBestEffortRequestId(rawRequest);
      return this.denyAndAudit({
        startTime,
        requestId,
        context,
        method: "unknown",
        operationKind: "unknown",
        target: "unknown",
        invocation: null,
        reasonCode: payloadCheck.reasonCode,
        matchedRuleId: null,
        detail: payloadCheck.detail,
        argumentsToLog: {}
      });
    }

    // Stage 2: JSON-RPC 2.0 Envelope Validation & Multi-Pass Canonicalization
    const envelopeCheck = validateAndNormalizeEnvelope(rawRequest, {
      rejectBatchRequests: this.config.payload?.rejectBatchRequests ?? true,
      maxDecodePasses: this.maxDecodePasses
    });

    if (!envelopeCheck.ok) {
      return this.denyAndAudit({
        startTime,
        requestId: envelopeCheck.requestId,
        context,
        method: envelopeCheck.method,
        operationKind: envelopeCheck.operationKind,
        target: envelopeCheck.target,
        invocation: null,
        reasonCode: envelopeCheck.reasonCode,
        matchedRuleId: null,
        detail: envelopeCheck.detail,
        argumentsToLog: {}
      });
    }

    const { invocation } = envelopeCheck;

    // Stage 3: Bounded-Memory Sliding-Window Rate Limiter
    const rateCheck = this.rateLimiter.check(
      context.principalId,
      invocation.target
    );
    if (!rateCheck.allowed) {
      return this.denyAndAudit({
        startTime,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: rateCheck.reasonCode,
        matchedRuleId: null,
        detail: rateCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    // Stage 4: Zero-Trust RBAC Policy Engine (with optional MCP Discovery fast-path)
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
        return this.denyAndAudit({
          startTime,
          requestId: invocation.requestId,
          context,
          method: invocation.method,
          operationKind: invocation.operationKind,
          target: invocation.target,
          invocation,
          reasonCode: policyDecision.reasonCode,
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
        return this.denyAndAudit({
          startTime,
          requestId: invocation.requestId,
          context,
          method: invocation.method,
          operationKind: invocation.operationKind,
          target: invocation.target,
          invocation,
          reasonCode: pathCheck.reasonCode,
          matchedRuleId,
          detail: pathCheck.detail,
          argumentsToLog: invocation.canonicalArguments
        });
      }
    }

    const commandCheck = this.commandGuard.check(invocation);
    if (!commandCheck.allowed) {
      return this.denyAndAudit({
        startTime,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: commandCheck.reasonCode,
        matchedRuleId,
        detail: commandCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    const ssrfCheck = this.ssrfGuard.check(invocation);
    if (!ssrfCheck.allowed) {
      return this.denyAndAudit({
        startTime,
        requestId: invocation.requestId,
        context,
        method: invocation.method,
        operationKind: invocation.operationKind,
        target: invocation.target,
        invocation,
        reasonCode: ssrfCheck.reasonCode,
        matchedRuleId,
        detail: ssrfCheck.detail,
        argumentsToLog: invocation.canonicalArguments
      });
    }

    // Stage 6: Cryptographic SHA-256 ALLOW Audit Record
    const latencyMs = performance.now() - startTime;
    const auditEntry = await this.auditLogger.record({
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
      invocation,
      auditEntry,
      error: null
    };
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
   * Wraps an MCP server request handler with inline firewall enforcement,
   * automatically returning sanitized JSON-RPC 2.0 error responses on policy or threat violations.
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
      return handler(request, inspection.invocation, context);
    };
  }

  /**
   * Returns a snapshot of sealed SHA-256 audit entries stored in the in-memory ring buffer.
   */
  public getAuditEntries(): readonly AuditEntry[] {
    return this.memoryAuditSink.getEntries();
  }

  /**
   * Cryptographically verifies the integrity of all retained in-memory audit records.
   */
  public async verifyAuditTrail(): Promise<ChainVerificationReport> {
    return verifyAuditChain(this.memoryAuditSink.getEntries(), {
      allowSubchain: this.memoryAuditSink.hasEvictedEntries()
    });
  }

  /**
   * Resets all in-memory sliding-window rate-limit counters.
   */
  public resetRateLimits(): void {
    this.rateLimiter.reset();
  }

  private async denyAndAudit(params: {
    readonly startTime: number;
    readonly requestId: JsonRpcId;
    readonly context: ExecutionContext;
    readonly method: string;
    readonly operationKind: NormalizedMcpInvocation["operationKind"];
    readonly target: string;
    readonly invocation: NormalizedMcpInvocation | null;
    readonly reasonCode: AuditReasonCode;
    readonly matchedRuleId: string | null;
    readonly detail: string;
    readonly argumentsToLog: Readonly<Record<string, unknown>>;
  }): Promise<InspectionResult> {
    const latencyMs = performance.now() - params.startTime;
    const auditEntry = await this.auditLogger.record({
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
      detail: params.detail,
      latencyMs,
      argumentsToLog: params.argumentsToLog
    });

    const error = new WardenError({
      reasonCode: params.reasonCode,
      internalDetail: params.detail,
      requestId: params.requestId,
      auditHash: auditEntry.hash
    });

    return {
      allowed: false,
      invocation: params.invocation,
      auditEntry,
      error
    };
  }
}
