/**
 * Standard JSON-RPC 2.0 protocol version identifier.
 */
export const JSONRPC_VERSION = "2.0" as const;

/**
 * Valid JSON-RPC 2.0 request identifier types.
 */
export type JsonRpcId = string | number | null;

/**
 * Standard and implementation-defined JSON-RPC 2.0 error codes
 * mapped to mcp-warden security outcomes.
 */
export const JsonRpcErrorCode = {
  /** Malformed JSON or invalid JSON-RPC 2.0 request structure */
  InvalidRequest: -32600,
  /** Requested MCP method does not exist or is unsupported */
  MethodNotFound: -32601,
  /** Invalid method parameters or schema validation failure */
  InvalidParams: -32602,
  /** Internal runtime or audit pipeline failure */
  InternalError: -32603,
  /** Server-defined: Access denied by RBAC or Fail-Closed policy */
  PolicyDenied: -32001,
  /** Server-defined: Security threat blocked (traversal, SSRF, injection, evasion) */
  ThreatDetected: -32002,
  /** Server-defined: Sliding-window rate limit exceeded */
  RateLimited: -32003,
  /** Server-defined: Payload byte size, depth, or key limit exceeded */
  PayloadTooLarge: -32004
} as const;

export type JsonRpcErrorCodeValue =
  (typeof JsonRpcErrorCode)[keyof typeof JsonRpcErrorCode];

/**
 * Immutable JSON-RPC 2.0 request envelope.
 */
export interface JsonRpcRequest<TParams = Record<string, unknown>> {
  readonly jsonrpc: typeof JSONRPC_VERSION;
  readonly id?: JsonRpcId;
  readonly method: string;
  readonly params?: TParams;
}

/**
 * Structured JSON-RPC 2.0 error object.
 */
export interface JsonRpcErrorObject {
  readonly code: JsonRpcErrorCodeValue;
  readonly message: string;
  readonly data?: Readonly<Record<string, unknown>>;
}

/**
 * Immutable JSON-RPC 2.0 success response envelope.
 */
export interface JsonRpcSuccessResponse<TResult = unknown> {
  readonly jsonrpc: typeof JSONRPC_VERSION;
  readonly id: JsonRpcId;
  readonly result: TResult;
}

/**
 * Immutable JSON-RPC 2.0 error response envelope.
 */
export interface JsonRpcErrorResponse {
  readonly jsonrpc: typeof JSONRPC_VERSION;
  readonly id: JsonRpcId;
  readonly error: JsonRpcErrorObject;
}

/**
 * Union type representing any valid JSON-RPC 2.0 response.
 */
export type JsonRpcResponse<TResult = unknown> =
  | JsonRpcSuccessResponse<TResult>
  | JsonRpcErrorResponse;
