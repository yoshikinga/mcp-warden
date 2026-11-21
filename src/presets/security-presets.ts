import type { PolicyRule, WardenConfig } from "../types/policy.js";

export interface StrictProductionPresetOptions {
  /** Permitted root directories for filesystem tools and file:// resources */
  readonly allowedRoots: readonly string[];
  /** Application-specific ALLOW and DENY RBAC rules */
  readonly rules?: readonly PolicyRule[];
  /** Sliding-window rate limit window in milliseconds (default: 60000) */
  readonly windowMs?: number;
  /** Maximum requests per (principalId, target) within windowMs (default: 60) */
  readonly maxRequestsPerWindow?: number;
  /** Maximum UTF-8 request payload size in bytes (default: 65536) */
  readonly maxPayloadBytes?: number;
  /** Additional sensitive argument keys to mask in SHA-256 audit records */
  readonly sensitiveAuditKeys?: readonly string[];
}

export interface ReadOnlyAgentPresetOptions {
  /** Optional root directories if the read-only agent inspects local files */
  readonly allowedRoots?: readonly string[];
  /** Roles granted read-only inspection access (default: ["*"]) */
  readonly readRoles?: readonly string[];
  /** Permitted read-oriented tool glob patterns */
  readonly allowedToolPatterns?: readonly string[];
  /** Permitted resource URI glob patterns (default: ["*"]) */
  readonly allowedResourcePatterns?: readonly string[];
  /** Maximum requests per minute per tool (default: 90) */
  readonly maxRequestsPerWindow?: number;
}

const DEFAULT_READ_TOOL_PATTERNS: readonly string[] = [
  "*:read*",
  "*:get*",
  "*:list*",
  "*:search*",
  "*:describe*",
  "read_*",
  "get_*",
  "list_*",
  "search_*",
  "describe_*"
];

const DESTRUCTIVE_TOOL_DENY_PATTERNS: readonly string[] = [
  "*write*",
  "*delete*",
  "*remove*",
  "*unlink*",
  "*update*",
  "*insert*",
  "*drop*",
  "*truncate*",
  "*alter*",
  "*exec*",
  "*shell*",
  "*bash*",
  "*spawn*",
  "*deploy*"
];

/**
 * Hardened production baseline enforcing fail-closed RBAC, 64 KiB payload caps,
 * lexical root-jail containment, command-injection blocking, and bitwise SSRF filtering.
 */
export function createStrictProductionPreset(
  options: StrictProductionPresetOptions
): WardenConfig {
  const baselineDenyRule: PolicyRule = {
    id: "preset-deny-dangerous-admin-wildcards",
    description: "Block raw shell and destructive system administration tools unless overridden by custom architecture.",
    effect: "DENY",
    roles: ["*"],
    operations: ["tool"],
    targets: ["system:shutdown*", "admin:drop_*", "debug:eval*"]
  };

  const config: WardenConfig = {
    rules: [baselineDenyRule, ...(options.rules ?? [])],
    maxDecodePasses: 3,
    allowDiscoveryMethods: true,
    payload: {
      enabled: true,
      maxBytes: options.maxPayloadBytes ?? 65_536,
      maxDepth: 12,
      maxKeys: 250,
      maxStringLength: 16_384,
      rejectBatchRequests: true
    },
    path: {
      enabled: true,
      allowedRoots: [...options.allowedRoots]
    },
    command: {
      enabled: true,
      scanAllStrings: true
    },
    ssrf: {
      enabled: true,
      allowedProtocols: ["https:", "http:"],
      blockPrivateNetworks: true,
      blockCloudMetadata: true
    },
    rateLimit: {
      enabled: true,
      windowMs: options.windowMs ?? 60_000,
      maxRequestsPerWindow: options.maxRequestsPerWindow ?? 60,
      maxTrackedKeys: 10_000
    },
    ...(options.sensitiveAuditKeys !== undefined
      ? { sensitiveAuditKeys: [...options.sensitiveAuditKeys] }
      : {})
  };

  return config;
}

/**
 * Turnkey policy preset for autonomous research, support, or observability agents
 * that must never mutate state, execute shell commands, or delete resources.
 */
export function createReadOnlyAgentPreset(
  options: ReadOnlyAgentPresetOptions = {}
): WardenConfig {
  const readRoles = options.readRoles ?? ["*"];
  const allowedTools = options.allowedToolPatterns ?? DEFAULT_READ_TOOL_PATTERNS;
  const allowedResources = options.allowedResourcePatterns ?? ["*"];

  const rules: PolicyRule[] = [
    {
      id: "readonly-explicit-deny-mutating-tools",
      description: "Explicitly deny all mutating, destructive, or shell-execution tools.",
      effect: "DENY",
      roles: ["*"],
      operations: ["tool"],
      targets: DESTRUCTIVE_TOOL_DENY_PATTERNS
    },
    {
      id: "readonly-allow-safe-inspection-tools",
      description: "Allow read/get/list/search inspection tools for authorized read roles.",
      effect: "ALLOW",
      roles: readRoles,
      operations: ["tool"],
      targets: allowedTools
    },
    {
      id: "readonly-allow-resource-reads",
      description: "Allow MCP resource reads subject to path-traversal and SSRF guards.",
      effect: "ALLOW",
      roles: readRoles,
      operations: ["resource"],
      targets: allowedResources
    },
    {
      id: "readonly-allow-prompts",
      description: "Allow retrieving MCP prompt templates.",
      effect: "ALLOW",
      roles: readRoles,
      operations: ["prompt"],
      targets: ["*"]
    }
  ];

  return {
    rules,
    maxDecodePasses: 3,
    allowDiscoveryMethods: true,
    payload: {
      enabled: true,
      maxBytes: 65_536,
      maxDepth: 12,
      maxKeys: 250,
      maxStringLength: 16_384,
      rejectBatchRequests: true
    },
    ...(options.allowedRoots !== undefined
      ? {
          path: {
            enabled: true,
            allowedRoots: [...options.allowedRoots]
          }
        }
      : {}),
    command: {
      enabled: true,
      scanAllStrings: true
    },
    ssrf: {
      enabled: true,
      allowedProtocols: ["https:", "http:"],
      blockPrivateNetworks: true,
      blockCloudMetadata: true
    },
    rateLimit: {
      enabled: true,
      windowMs: 60_000,
      maxRequestsPerWindow: options.maxRequestsPerWindow ?? 90,
      maxTrackedKeys: 10_000
    }
  };
}
