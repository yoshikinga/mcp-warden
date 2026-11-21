import type { JsonRpcId } from "./jsonrpc.js";

/**
 * Primary Model Context Protocol (MCP) invocation categories.
 */
export type McpOperationKind =
  | "tool"
  | "resource"
  | "prompt"
  | "lifecycle"
  | "unknown";

/**
 * MCP `tools/call` parameter payload shape.
 */
export interface McpToolCallParams {
  readonly name: string;
  readonly arguments?: Readonly<Record<string, unknown>>;
}

/**
 * MCP `resources/read` parameter payload shape.
 */
export interface McpResourceReadParams {
  readonly uri: string;
}

/**
 * MCP `prompts/get` parameter payload shape.
 */
export interface McpPromptGetParams {
  readonly name: string;
  readonly arguments?: Readonly<Record<string, string>>;
}

/**
 * Caller identity and runtime execution context supplied by the MCP host/transport.
 */
export interface ExecutionContext {
  /** Unique identifier of the calling user, service account, or agent identity */
  readonly principalId: string;
  /** Assigned RBAC roles (e.g., ["read-only", "support-agent"]) */
  readonly roles: readonly string[];
  /** Optional session or conversation identifier for correlation */
  readonly sessionId?: string;
  /** Optional transport type (e.g., "stdio", "sse", "streamable-http") */
  readonly transport?: string;
  /** Optional client IP address when invoked over network transport */
  readonly clientIp?: string;
  /** Optional caller-supplied metadata */
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Normalized representation of an incoming MCP request after envelope validation
 * and multi-pass canonicalization.
 */
export interface NormalizedMcpInvocation {
  readonly requestId: JsonRpcId;
  readonly method: string;
  readonly operationKind: McpOperationKind;
  /** Canonical target identifier (tool name, resource URI, prompt name, or method) */
  readonly target: string;
  /** Raw arguments preserved untouched for downstream execution when allowed */
  readonly rawArguments: Readonly<Record<string, unknown>>;
  /** Canonicalized arguments used exclusively by security guards and policy rules */
  readonly canonicalArguments: Readonly<Record<string, unknown>>;
}
