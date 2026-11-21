import type { JsonRpcId } from "./jsonrpc.js";
import type { McpOperationKind } from "./mcp.js";

/**
 * Recorded enforcement outcome for an MCP invocation.
 */
export type AuditDecisionOutcome = "ALLOW" | "DENY";

/**
 * Standardized machine-readable reason codes for audit records.
 */
export type AuditReasonCode =
  | "ALLOWED_BY_POLICY"
  | "ALLOWED_DISCOVERY"
  | "INVALID_ENVELOPE"
  | "PAYLOAD_LIMIT_EXCEEDED"
  | "EVASION_DETECTED"
  | "RATE_LIMIT_EXCEEDED"
  | "POLICY_EXPLICIT_DENY"
  | "POLICY_NO_MATCH_FAIL_CLOSED"
  | "ARGUMENT_CONSTRAINT_FAILED"
  | "PATH_TRAVERSAL_BLOCKED"
  | "SENSITIVE_FILE_BLOCKED"
  | "COMMAND_INJECTION_BLOCKED"
  | "SSRF_BLOCKED";

/**
 * Unsigned payload fields hashed into the cryptographic audit chain.
 */
export interface UnsignedAuditEntry {
  /** Monotonically increasing 0-based sequence index */
  readonly sequence: number;
  /** ISO-8601 UTC timestamp */
  readonly timestamp: string;
  /** JSON-RPC request ID */
  readonly requestId: JsonRpcId;
  /** Authenticated caller principal ID */
  readonly principalId: string;
  /** Caller session ID if provided */
  readonly sessionId: string | null;
  /** JSON-RPC method name */
  readonly method: string;
  /** Normalized MCP operation category */
  readonly operationKind: McpOperationKind;
  /** Target tool name, resource URI, or method */
  readonly target: string;
  /** Enforcement decision */
  readonly decision: AuditDecisionOutcome;
  /** Standardized reason code */
  readonly reasonCode: AuditReasonCode;
  /** Matched RBAC rule ID when applicable */
  readonly matchedRuleId: string | null;
  /** Internal diagnostic message (never leaked to external LLM clients) */
  readonly detail: string;
  /** Inspection pipeline execution latency in milliseconds */
  readonly latencyMs: number;
  /** Secret-scrubbed snapshot of canonicalized arguments */
  readonly redactedArguments: Readonly<Record<string, unknown>>;
  /** SHA-256 hex digest of the preceding entry (or 64 zeros for genesis) */
  readonly prevHash: string;
}

/**
 * Tamper-evident audit record sealed with a SHA-256 chain hash.
 */
export interface AuditEntry extends UnsignedAuditEntry {
  /** SHA-256(prevHash + canonicalJson(UnsignedAuditEntry)) in lowercase hex */
  readonly hash: string;
}

/**
 * Pluggable destination sink for persisting sealed audit records.
 */
export interface AuditSink {
  write(entry: AuditEntry): void | Promise<void>;
}

/**
 * Verification report produced by `verifyAuditChain`.
 */
export interface ChainVerificationReport {
  readonly valid: boolean;
  readonly checkedCount: number;
  readonly brokenAtSequence: number | null;
  readonly reason: string | null;
}
