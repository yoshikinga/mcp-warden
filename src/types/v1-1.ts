import type { AuditEntry } from "./audit.js";
import type { JsonRpcId } from "./jsonrpc.js";
import type { McpOperationKind } from "./mcp.js";
import type { WardenConfig } from "./policy.js";

/**
 * Gateway enforcement operating mode:
 * - ENFORCE: Blocks policy/threat violations immediately (Fail-Closed).
 * - DRY_RUN: Shadow mode for B2B rollout; logs WOULD_DENY violations and fires hooks without blocking traffic.
 */
export type EnforcementMode = "ENFORCE" | "DRY_RUN";

/**
 * Extended v1.1 threat and operational reason codes for full-duplex MCP defense.
 */
export type V11ReasonCode =
  | "UNICODE_TROJAN_DETECTED"
  | "TOOL_POISONING_DETECTED"
  | "TOOL_RUG_PULL_DETECTED"
  | "EGRESS_SECRET_BLOCKED"
  | "EGRESS_SECRET_REDACTED"
  | "CIRCUIT_BREAKER_OPEN";

/**
 * Configuration for UnicodeTrojanGuard (Trojan Source CVE-2021-42574 & ASCII Tag Smuggling).
 */
export interface UnicodeGuardConfig {
  readonly enabled?: boolean;
  /** Block bidirectional override/isolate controls U+202A..U+202E, U+2066..U+2069, U+061C, U+200E, U+200F (default: true) */
  readonly blockBidiControls?: boolean;
  /** Block invisible zero-width joiners/spaces U+200B..U+200D, U+2060, U+FEFF (default: true) */
  readonly blockZeroWidthChars?: boolean;
  /** Block Unicode Plane 14 Tag characters U+E0000..U+E007F used for invisible prompt smuggling (default: true) */
  readonly blockTagCharacters?: boolean;
}

/**
 * Result returned by UnicodeTrojanGuard.
 */
export type UnicodeGuardResult =
  | {
      readonly allowed: true;
    }
  | {
      readonly allowed: false;
      readonly reasonCode: "UNICODE_TROJAN_DETECTED";
      readonly detail: string;
      readonly fieldPath: string;
      readonly codePointHex: string;
    };

/**
 * Standard MCP tool descriptor returned inside `tools/list` responses.
 */
export interface McpToolDefinition {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: Readonly<Record<string, unknown>>;
}

/**
 * Configuration for ToolIntegrityGuard defending against MCP Tool Poisoning & Rug-Pulls.
 */
export interface ToolIntegrityConfig {
  readonly enabled?: boolean;
  /** Scan tool and schema descriptions for covert prompt-override directives (default: true) */
  readonly detectDescriptionInjection?: boolean;
  /** Pin SHA-256 canonical digests on first `tools/list` observation per server (default: true) */
  readonly pinOnFirstObservation?: boolean;
  /** Allow previously unseen tool names after a server's catalog has been pinned (default: false) */
  readonly allowDynamicNewTools?: boolean;
  /** Optional static pre-approved SHA-256 digests keyed by tool name */
  readonly trustedFingerprints?: Readonly<Record<string, string>>;
  /** Maximum distinct upstream MCP server catalogs retained in memory (default: 500) */
  readonly maxTrackedServers?: number;
}

/**
 * Outcome returned by ToolIntegrityGuard when inspecting an MCP `tools/list` catalog.
 */
export type ToolIntegrityCheckResult =
  | {
      readonly allowed: true;
      readonly serverId: string;
      readonly newlyPinned: boolean;
      readonly fingerprints: Readonly<Record<string, string>>;
    }
  | {
      readonly allowed: false;
      readonly serverId: string;
      readonly reasonCode: "TOOL_POISONING_DETECTED" | "TOOL_RUG_PULL_DETECTED";
      readonly violatingToolName: string;
      readonly detail: string;
      readonly fingerprints: Readonly<Record<string, string>>;
    };

/**
 * Enforcement action taken when EgressSecretGuard detects credentials in outbound responses.
 */
export type EgressAction = "REDACT" | "BLOCK";

/**
 * Built-in credential pattern classifications detected by EgressSecretGuard.
 */
export type SecretDetectorKind =
  | "AWS_ACCESS_KEY"
  | "GITHUB_TOKEN"
  | "ANTHROPIC_KEY"
  | "OPENAI_OR_API_KEY"
  | "STRIPE_LIVE_KEY"
  | "SLACK_TOKEN"
  | "GOOGLE_API_KEY"
  | "PRIVATE_KEY_PEM"
  | "JWT_BEARER"
  | "DATABASE_URI_CREDENTIALS"
  | "CUSTOM_PREFIX";

/**
 * Metadata describing a detected secret leak without storing the raw secret value.
 */
export interface SecretFinding {
  readonly kind: SecretDetectorKind;
  readonly fieldPath: string;
  /** Non-sensitive prefix preview (e.g., "AKIA****") */
  readonly preview: string;
}

/**
 * Configuration for EgressSecretGuard inspecting MCP tool/resource responses.
 */
export interface EgressSecretConfig {
  readonly enabled?: boolean;
  /** REDACT masks secrets in-flight; BLOCK rejects the entire response (default: "REDACT") */
  readonly action?: EgressAction;
  /** Mask string substituted for redacted credentials (default: "[REDACTED_SECRET]") */
  readonly replacementMask?: string;
  /** Detect three-part base64url JSON Web Tokens starting with eyJ (default: true) */
  readonly detectJwtTokens?: boolean;
  /** Additional enterprise token prefixes to scrub (e.g., ["acme_live_"]) */
  readonly customSecretPrefixes?: readonly string[];
  /** Maximum object traversal depth on outbound payloads (default: 16) */
  readonly maxScanDepth?: number;
}

/**
 * Outcome returned by EgressSecretGuard.
 */
export interface EgressInspectionResult<TPayload = unknown> {
  readonly allowed: boolean;
  readonly mutated: boolean;
  readonly sanitizedPayload: TPayload;
  readonly findings: readonly SecretFinding[];
  readonly reasonCode: "EGRESS_SECRET_BLOCKED" | "EGRESS_SECRET_REDACTED" | null;
  readonly detail: string;
}

/**
 * Behavioral quarantine states for SessionCircuitBreaker.
 */
export type CircuitBreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";

/**
 * Configuration for SessionCircuitBreaker isolating probing or hijacked agent sessions.
 */
export interface CircuitBreakerConfig {
  readonly enabled?: boolean;
  /** Consecutive/windowed security violations required to trip circuit OPEN (default: 5) */
  readonly failureThreshold?: number;
  /** Sliding window in milliseconds for counting violations (default: 30000) */
  readonly failureWindowMs?: number;
  /** Quarantine duration in milliseconds before allowing a HALF_OPEN probe (default: 60000) */
  readonly cooldownMs?: number;
  /** Hard ceiling on tracked session keys in memory (default: 10000) */
  readonly maxTrackedSessions?: number;
}

/**
 * Diagnostic state snapshot for a tracked session or principal key.
 */
export interface CircuitBreakerSnapshot {
  readonly key: string;
  readonly state: CircuitBreakerState;
  readonly recentViolations: number;
  readonly openedAtMs: number | null;
  readonly remainingCooldownMs: number;
}

/**
 * Result returned by SessionCircuitBreaker before pipeline execution.
 */
export type CircuitBreakerCheckResult =
  | {
      readonly allowed: true;
      readonly state: "CLOSED" | "HALF_OPEN";
    }
  | {
      readonly allowed: false;
      readonly state: "OPEN" | "HALF_OPEN";
      readonly reasonCode: "CIRCUIT_BREAKER_OPEN";
      readonly remainingCooldownMs: number;
      readonly detail: string;
    };

/**
 * Optional secret-keyed HMAC-SHA256 signing configuration for tamper-proof audit chains.
 */
export interface HmacAuditConfig {
  /** UTF-8 signing secret (>= 16 chars recommended) used with Web Crypto HMAC-SHA256 */
  readonly secretKey: string;
  /** Identifier of the active signing key for key-rotation tracking (default: "default") */
  readonly keyId?: string;
}

/**
 * Structured real-time telemetry event emitted on policy or threat violations.
 */
export interface ViolationEvent {
  readonly timestamp: string;
  readonly mode: EnforcementMode;
  readonly blocked: boolean;
  readonly requestId: JsonRpcId;
  readonly principalId: string;
  readonly sessionId: string | null;
  readonly operationKind: McpOperationKind;
  readonly target: string;
  readonly reasonCode: string;
  readonly auditEntry: AuditEntry;
}

/**
 * Callback invoked asynchronously/synchronously whenever a security violation occurs.
 */
export type ViolationHook = (event: ViolationEvent) => void | Promise<void>;

/**
 * Point-in-time operational telemetry counters exposed by McpWarden.
 */
export interface WardenMetricsSnapshot {
  readonly totalInspected: number;
  readonly totalAllowed: number;
  readonly totalDenied: number;
  readonly totalDryRunWouldDeny: number;
  readonly totalEgressScrubbed: number;
  readonly totalCircuitBreakerBlocks: number;
  readonly reasonsCount: Readonly<Record<string, number>>;
}

/**
 * Extended v1.1 configuration contract backward-compatible with v1.0 WardenConfig.
 */
export interface WardenV11Config extends WardenConfig {
  readonly mode?: EnforcementMode;
  readonly unicode?: UnicodeGuardConfig;
  readonly toolIntegrity?: ToolIntegrityConfig;
  readonly egress?: EgressSecretConfig;
  readonly circuitBreaker?: CircuitBreakerConfig;
  readonly hmacAudit?: HmacAuditConfig;
}
