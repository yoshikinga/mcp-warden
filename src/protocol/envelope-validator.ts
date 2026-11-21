import type { AuditReasonCode } from "../types/audit.js";
import { JSONRPC_VERSION, type JsonRpcId } from "../types/jsonrpc.js";
import type { McpOperationKind, NormalizedMcpInvocation } from "../types/mcp.js";
import { canonicalizeRecord, canonicalizeString } from "./canonicalizer.js";

/**
 * Standard MCP discovery and lifecycle methods.
 */
const MCP_LIFECYCLE_METHODS: ReadonlySet<string> = new Set([
  "initialize",
  "notifications/initialized",
  "notifications/cancelled",
  "ping",
  "tools/list",
  "resources/list",
  "resources/templates/list",
  "prompts/list",
  "logging/setLevel",
  "completion/complete"
]);

export type EnvelopeValidationResult =
  | {
      readonly ok: true;
      readonly invocation: NormalizedMcpInvocation;
    }
  | {
      readonly ok: false;
      readonly requestId: JsonRpcId;
      readonly method: string;
      readonly operationKind: McpOperationKind;
      readonly target: string;
      readonly reasonCode: Extract<
        AuditReasonCode,
        "INVALID_ENVELOPE" | "EVASION_DETECTED"
      >;
      readonly detail: string;
    };

export interface EnvelopeValidatorOptions {
  readonly rejectBatchRequests?: boolean;
  readonly maxDecodePasses?: number;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function extractSafeRequestId(candidate: unknown): JsonRpcId {
  if (
    typeof candidate === "string" ||
    (typeof candidate === "number" && Number.isFinite(candidate)) ||
    candidate === null
  ) {
    return candidate;
  }
  return null;
}

/**
 * Validates raw JSON strings or parsed objects against JSON-RPC 2.0 and MCP structural rules,
 * returning a canonicalized NormalizedMcpInvocation ready for RBAC and threat inspection.
 */
export function validateAndNormalizeEnvelope(
  rawInput: unknown,
  options: EnvelopeValidatorOptions = {}
): EnvelopeValidationResult {
  const rejectBatch = options.rejectBatchRequests ?? true;
  const maxDecodePasses = options.maxDecodePasses ?? 3;

  let parsed: unknown = rawInput;
  if (typeof rawInput === "string") {
    try {
      parsed = JSON.parse(rawInput) as unknown;
    } catch {
      return {
        ok: false,
        requestId: null,
        method: "unknown",
        operationKind: "unknown",
        target: "unknown",
        reasonCode: "INVALID_ENVELOPE",
        detail: "Failed to parse incoming payload as valid JSON."
      };
    }
  }

  if (Array.isArray(parsed)) {
    return {
      ok: false,
      requestId: null,
      method: "batch",
      operationKind: "unknown",
      target: "batch",
      reasonCode: "INVALID_ENVELOPE",
      detail: rejectBatch
        ? "JSON-RPC batch array requests are rejected by security policy."
        : "Batch array must be unpacked into individual JSON-RPC envelopes."
    };
  }

  if (!isPlainObject(parsed)) {
    return {
      ok: false,
      requestId: null,
      method: "unknown",
      operationKind: "unknown",
      target: "unknown",
      reasonCode: "INVALID_ENVELOPE",
      detail: "JSON-RPC 2.0 request envelope must be a plain JSON object."
    };
  }

  const rawId = parsed["id"];
  const requestId = extractSafeRequestId(rawId);

  if (
    rawId !== undefined &&
    rawId !== null &&
    typeof rawId !== "string" &&
    (typeof rawId !== "number" || !Number.isFinite(rawId))
  ) {
    return {
      ok: false,
      requestId: null,
      method: "unknown",
      operationKind: "unknown",
      target: "unknown",
      reasonCode: "INVALID_ENVELOPE",
      detail: "JSON-RPC 2.0 'id' field must be a string, finite number, or null."
    };
  }

  if (parsed["jsonrpc"] !== JSONRPC_VERSION) {
    return {
      ok: false,
      requestId,
      method: "unknown",
      operationKind: "unknown",
      target: "unknown",
      reasonCode: "INVALID_ENVELOPE",
      detail: "Missing or unsupported 'jsonrpc' version; expected '2.0'."
    };
  }

  const rawMethod = parsed["method"];
  if (typeof rawMethod !== "string" || rawMethod.trim().length === 0) {
    return {
      ok: false,
      requestId,
      method: "unknown",
      operationKind: "unknown",
      target: "unknown",
      reasonCode: "INVALID_ENVELOPE",
      detail: "JSON-RPC 2.0 'method' must be a non-empty string."
    };
  }

  const canonicalMethodResult = canonicalizeString(rawMethod, maxDecodePasses);
  if (!canonicalMethodResult.ok) {
    return {
      ok: false,
      requestId,
      method: rawMethod,
      operationKind: "unknown",
      target: rawMethod,
      reasonCode: canonicalMethodResult.reasonCode,
      detail: canonicalMethodResult.detail
    };
  }
  const method = canonicalMethodResult.value;

  const rawParams = parsed["params"];
  if (rawParams !== undefined && !isPlainObject(rawParams)) {
    return {
      ok: false,
      requestId,
      method,
      operationKind: "unknown",
      target: method,
      reasonCode: "INVALID_ENVELOPE",
      detail: "MCP JSON-RPC 'params' must be a plain object when provided."
    };
  }

  if (method === "tools/call") {
    if (rawParams === undefined) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "tool",
        target: "unknown",
        reasonCode: "INVALID_ENVELOPE",
        detail: "MCP 'tools/call' requires a 'params' object containing tool 'name'."
      };
    }

    const toolName = rawParams["name"];
    if (typeof toolName !== "string" || toolName.trim().length === 0) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "tool",
        target: "unknown",
        reasonCode: "INVALID_ENVELOPE",
        detail: "MCP 'tools/call' parameter 'name' must be a non-empty string."
      };
    }

    const canonicalTarget = canonicalizeString(toolName, maxDecodePasses);
    if (!canonicalTarget.ok) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "tool",
        target: toolName,
        reasonCode: canonicalTarget.reasonCode,
        detail: canonicalTarget.detail
      };
    }

    const rawToolArgs = rawParams["arguments"];
    if (rawToolArgs !== undefined && !isPlainObject(rawToolArgs)) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "tool",
        target: canonicalTarget.value,
        reasonCode: "INVALID_ENVELOPE",
        detail: "MCP 'tools/call' field 'arguments' must be a plain object when provided."
      };
    }

    const safeRawArgs: Record<string, unknown> = rawToolArgs ?? {};
    const canonicalArgs = canonicalizeRecord(safeRawArgs, maxDecodePasses);
    if (!canonicalArgs.ok) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "tool",
        target: canonicalTarget.value,
        reasonCode: canonicalArgs.reasonCode,
        detail: canonicalArgs.detail
      };
    }

    return {
      ok: true,
      invocation: {
        requestId,
        method,
        operationKind: "tool",
        target: canonicalTarget.value,
        rawArguments: safeRawArgs,
        canonicalArguments: canonicalArgs.value
      }
    };
  }

  if (method === "resources/read") {
    const resourceUri = rawParams?.["uri"];
    if (typeof resourceUri !== "string" || resourceUri.trim().length === 0) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "resource",
        target: "unknown",
        reasonCode: "INVALID_ENVELOPE",
        detail: "MCP 'resources/read' requires a non-empty string 'uri' parameter."
      };
    }

    const canonicalUri = canonicalizeString(resourceUri, maxDecodePasses);
    if (!canonicalUri.ok) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "resource",
        target: resourceUri,
        reasonCode: canonicalUri.reasonCode,
        detail: canonicalUri.detail
      };
    }

    const safeRawArgs: Record<string, unknown> = rawParams ?? { uri: resourceUri };
    const canonicalArgs = canonicalizeRecord(safeRawArgs, maxDecodePasses);
    if (!canonicalArgs.ok) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "resource",
        target: canonicalUri.value,
        reasonCode: canonicalArgs.reasonCode,
        detail: canonicalArgs.detail
      };
    }

    return {
      ok: true,
      invocation: {
        requestId,
        method,
        operationKind: "resource",
        target: canonicalUri.value,
        rawArguments: safeRawArgs,
        canonicalArguments: canonicalArgs.value
      }
    };
  }

  if (method === "prompts/get") {
    const promptName = rawParams?.["name"];
    if (typeof promptName !== "string" || promptName.trim().length === 0) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "prompt",
        target: "unknown",
        reasonCode: "INVALID_ENVELOPE",
        detail: "MCP 'prompts/get' requires a non-empty string 'name' parameter."
      };
    }

    const canonicalPrompt = canonicalizeString(promptName, maxDecodePasses);
    if (!canonicalPrompt.ok) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "prompt",
        target: promptName,
        reasonCode: canonicalPrompt.reasonCode,
        detail: canonicalPrompt.detail
      };
    }

    const rawPromptArgs = rawParams?.["arguments"];
    if (rawPromptArgs !== undefined && !isPlainObject(rawPromptArgs)) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "prompt",
        target: canonicalPrompt.value,
        reasonCode: "INVALID_ENVELOPE",
        detail: "MCP 'prompts/get' field 'arguments' must be a plain object when provided."
      };
    }

    const safeRawArgs: Record<string, unknown> = rawPromptArgs ?? {};
    const canonicalArgs = canonicalizeRecord(safeRawArgs, maxDecodePasses);
    if (!canonicalArgs.ok) {
      return {
        ok: false,
        requestId,
        method,
        operationKind: "prompt",
        target: canonicalPrompt.value,
        reasonCode: canonicalArgs.reasonCode,
        detail: canonicalArgs.detail
      };
    }

    return {
      ok: true,
      invocation: {
        requestId,
        method,
        operationKind: "prompt",
        target: canonicalPrompt.value,
        rawArguments: safeRawArgs,
        canonicalArguments: canonicalArgs.value
      }
    };
  }

  const operationKind: McpOperationKind = MCP_LIFECYCLE_METHODS.has(method)
    ? "lifecycle"
    : "unknown";
  const safeRawArgs: Record<string, unknown> = rawParams ?? {};
  const canonicalArgs = canonicalizeRecord(safeRawArgs, maxDecodePasses);
  if (!canonicalArgs.ok) {
    return {
      ok: false,
      requestId,
      method,
      operationKind,
      target: method,
      reasonCode: canonicalArgs.reasonCode,
      detail: canonicalArgs.detail
    };
  }

  return {
    ok: true,
    invocation: {
      requestId,
      method,
      operationKind,
      target: method,
      rawArguments: safeRawArgs,
      canonicalArguments: canonicalArgs.value
    }
  };
}
