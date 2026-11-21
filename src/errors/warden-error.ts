import type { AuditReasonCode } from "../types/audit.js";
import {
  JSONRPC_VERSION,
  JsonRpcErrorCode,
  type JsonRpcErrorCodeValue,
  type JsonRpcErrorResponse,
  type JsonRpcId
} from "../types/jsonrpc.js";

/**
 * Maps internal audit reason codes to standard JSON-RPC 2.0 error codes.
 */
export function mapReasonToJsonRpcCode(
  reasonCode: AuditReasonCode
): JsonRpcErrorCodeValue {
  switch (reasonCode) {
    case "INVALID_ENVELOPE":
      return JsonRpcErrorCode.InvalidRequest;
    case "PAYLOAD_LIMIT_EXCEEDED":
      return JsonRpcErrorCode.PayloadTooLarge;
    case "ARGUMENT_CONSTRAINT_FAILED":
      return JsonRpcErrorCode.InvalidParams;
    case "RATE_LIMIT_EXCEEDED":
      return JsonRpcErrorCode.RateLimited;
    case "POLICY_EXPLICIT_DENY":
    case "POLICY_NO_MATCH_FAIL_CLOSED":
      return JsonRpcErrorCode.PolicyDenied;
    case "EVASION_DETECTED":
    case "PATH_TRAVERSAL_BLOCKED":
    case "SENSITIVE_FILE_BLOCKED":
    case "COMMAND_INJECTION_BLOCKED":
    case "SSRF_BLOCKED":
      return JsonRpcErrorCode.ThreatDetected;
    case "ALLOWED_BY_POLICY":
    case "ALLOWED_DISCOVERY":
      return JsonRpcErrorCode.InternalError;
  }
}

/**
 * Returns a sanitized, non-leaky client message safe to expose to LLM agents.
 * Internal filesystem roots, matched rule IDs, and internal host details are withheld.
 */
export function toSafeClientMessage(reasonCode: AuditReasonCode): string {
  switch (reasonCode) {
    case "INVALID_ENVELOPE":
      return "Malformed JSON-RPC 2.0 or MCP request envelope.";
    case "PAYLOAD_LIMIT_EXCEEDED":
      return "Request payload exceeds configured size or structural limits.";
    case "ARGUMENT_CONSTRAINT_FAILED":
      return "Tool arguments failed security policy parameter constraints.";
    case "RATE_LIMIT_EXCEEDED":
      return "Invocation rate limit exceeded for principal or target.";
    case "POLICY_EXPLICIT_DENY":
    case "POLICY_NO_MATCH_FAIL_CLOSED":
      return "Access denied by MCP security policy.";
    case "EVASION_DETECTED":
      return "Request blocked due to suspicious encoding or control characters.";
    case "PATH_TRAVERSAL_BLOCKED":
    case "SENSITIVE_FILE_BLOCKED":
      return "Filesystem path access denied by security boundary.";
    case "COMMAND_INJECTION_BLOCKED":
      return "Argument blocked due to disallowed shell metacharacters.";
    case "SSRF_BLOCKED":
      return "Outbound network target blocked by SSRF protection policy.";
    case "ALLOWED_BY_POLICY":
    case "ALLOWED_DISCOVERY":
      return "Unexpected internal policy evaluation state.";
  }
}

/**
 * Structured error thrown by `McpWarden.assertAllowed()` and `McpWarden.wrap()`.
 */
export class WardenError extends Error {
  public readonly reasonCode: AuditReasonCode;
  public readonly jsonRpcCode: JsonRpcErrorCodeValue;
  public readonly safeMessage: string;
  public readonly requestId: JsonRpcId;
  public readonly auditHash: string | null;

  public constructor(params: {
    readonly reasonCode: AuditReasonCode;
    readonly internalDetail: string;
    readonly requestId?: JsonRpcId;
    readonly auditHash?: string | null;
  }) {
    super(params.internalDetail);
    this.name = "WardenError";
    this.reasonCode = params.reasonCode;
    this.jsonRpcCode = mapReasonToJsonRpcCode(params.reasonCode);
    this.safeMessage = toSafeClientMessage(params.reasonCode);
    this.requestId = params.requestId ?? null;
    this.auditHash = params.auditHash ?? null;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Serializes the error into a sanitized JSON-RPC 2.0 error envelope
   * suitable for direct transmission back to an MCP client.
   */
  public toJsonRpcErrorResponse(): JsonRpcErrorResponse {
    const data: Record<string, unknown> = {
      reasonCode: this.reasonCode
    };
    if (this.auditHash !== null) {
      data["auditHash"] = this.auditHash;
    }

    return {
      jsonrpc: JSONRPC_VERSION,
      id: this.requestId,
      error: {
        code: this.jsonRpcCode,
        message: this.safeMessage,
        data
      }
    };
  }
}
