import type { McpOperationKind } from "./mcp.js";

/**
 * Policy rule evaluation effect.
 * Explicit DENY always supersedes ALLOW; unmatched requests fail closed.
 */
export type PolicyEffect = "ALLOW" | "DENY";

/**
 * Supported primitive argument types for parameter constraint enforcement.
 */
export type ArgumentExpectedType =
  | "string"
  | "number"
  | "boolean"
  | "object"
  | "array";

/**
 * Declarative constraint applied to a single tool/prompt argument field.
 */
export interface ArgumentConstraint {
  /** Whether the argument key must be present and non-nullish */
  readonly required?: boolean;
  /** Expected runtime type */
  readonly type?: ArgumentExpectedType;
  /** Whitelist of exact scalar values permitted */
  readonly enum?: readonly (string | number | boolean)[];
  /** Minimum numeric value (inclusive) when type is "number" */
  readonly min?: number;
  /** Maximum numeric value (inclusive) when type is "number" */
  readonly max?: number;
  /** Maximum string length when type is "string" */
  readonly maxLength?: number;
  /** Required prefix match (at least one must match) when type is "string" */
  readonly allowedPrefixes?: readonly string[];
}

/**
 * A single Zero-Trust RBAC policy rule governing MCP operations.
 */
export interface PolicyRule {
  /** Unique rule identifier recorded in audit trails */
  readonly id: string;
  /** Human-readable description of the security intent */
  readonly description?: string;
  /** ALLOW or DENY */
  readonly effect: PolicyEffect;
  /** Roles to which this rule applies; use ["*"] to match all roles */
  readonly roles: readonly string[];
  /** Optional filter on MCP operation kind; defaults to all kinds if omitted */
  readonly operations?: readonly McpOperationKind[];
  /** Glob patterns matching tool names or resource URIs (supports * and ?) */
  readonly targets: readonly string[];
  /** Optional per-argument constraints checked when rule matches */
  readonly argumentConstraints?: Readonly<Record<string, ArgumentConstraint>>;
}

/**
 * Result returned by the RBAC PolicyEngine.
 */
export interface PolicyDecision {
  readonly allowed: boolean;
  readonly matchedRuleId: string | null;
  readonly reason: string;
}

/**
 * Configuration for PayloadGuard DoS protection.
 */
export interface PayloadGuardConfig {
  readonly enabled?: boolean;
  /** Maximum UTF-8 byte length of the serialized request payload (default: 65536) */
  readonly maxBytes?: number;
  /** Maximum JSON object/array nesting depth (default: 12) */
  readonly maxDepth?: number;
  /** Maximum total object keys across the entire payload (default: 250) */
  readonly maxKeys?: number;
  /** Maximum length of any single string value (default: 16384) */
  readonly maxStringLength?: number;
  /** Reject JSON-RPC array batch requests (default: true) */
  readonly rejectBatchRequests?: boolean;
}

/**
 * Configuration for lexical Root-Jail PathTraversalGuard.
 */
export interface PathGuardConfig {
  readonly enabled?: boolean;
  /** List of permitted root directories; if empty, all filesystem paths are blocked */
  readonly allowedRoots: readonly string[];
  /** Additional sensitive file basenames or suffixes to deny */
  readonly blockedFilePatterns?: readonly string[];
  /** Argument field names explicitly treated as filesystem paths */
  readonly pathArgumentKeys?: readonly string[];
}

/**
 * Configuration for CommandInjectionGuard.
 */
export interface CommandGuardConfig {
  readonly enabled?: boolean;
  /** Argument field names inspected for shell metacharacters */
  readonly commandArgumentKeys?: readonly string[];
  /** When true, scans all string arguments across every tool (default: true) */
  readonly scanAllStrings?: boolean;
}

/**
 * Configuration for bitwise IPv4/IPv6 SsrfGuard.
 */
export interface SsrfGuardConfig {
  readonly enabled?: boolean;
  /** Permitted URL schemes (default: ["https:", "http:"]) */
  readonly allowedProtocols?: readonly string[];
  /** Block RFC1918, loopback, link-local, and IPv6 private ranges (default: true) */
  readonly blockPrivateNetworks?: boolean;
  /** Block cloud instance metadata endpoints such as 169.254.169.254 (default: true) */
  readonly blockCloudMetadata?: boolean;
  /** Explicitly allowlisted hostnames bypassing private network checks */
  readonly allowedHosts?: readonly string[];
}

/**
 * Configuration for SlidingWindowRateLimiter.
 */
export interface RateLimitConfig {
  readonly enabled?: boolean;
  /** Sliding window duration in milliseconds (default: 60000) */
  readonly windowMs?: number;
  /** Maximum requests per (principalId, target) within windowMs (default: 60) */
  readonly maxRequestsPerWindow?: number;
  /** Per-target overrides supporting wildcard globs (e.g., { "db:write_*": 5 }) */
  readonly targetOverrides?: Readonly<Record<string, number>>;
  /** Hard ceiling on tracked keys in memory to prevent RAM exhaustion (default: 10000) */
  readonly maxTrackedKeys?: number;
}

/**
 * Complete configuration object accepted by McpWarden.
 */
export interface WardenConfig {
  /** Ordered list of RBAC policy rules */
  readonly rules: readonly PolicyRule[];
  /** Maximum URI percent-decoding passes in canonicalizer (default: 3) */
  readonly maxDecodePasses?: number;
  /** Allow standard MCP discovery methods (initialize, tools/list, etc.) without explicit rule (default: true) */
  readonly allowDiscoveryMethods?: boolean;
  readonly payload?: PayloadGuardConfig;
  readonly path?: PathGuardConfig;
  readonly command?: CommandGuardConfig;
  readonly ssrf?: SsrfGuardConfig;
  readonly rateLimit?: RateLimitConfig;
  /** Additional argument keys whose values must be masked in audit logs */
  readonly sensitiveAuditKeys?: readonly string[];
}
