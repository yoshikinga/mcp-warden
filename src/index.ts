// Core Gateway
export {
  McpWarden,
  type InspectionResult,
  type McpWardenRuntimeOptions
} from "./warden.js";

// Security Presets
export {
  createReadOnlyAgentPreset,
  createStrictProductionPreset,
  type ReadOnlyAgentPresetOptions,
  type StrictProductionPresetOptions
} from "./presets/security-presets.js";

// Errors
export {
  WardenError,
  mapReasonToJsonRpcCode,
  toSafeClientMessage
} from "./errors/warden-error.js";

// Protocol & Canonicalization
export {
  canonicalizeRecord,
  canonicalizeString,
  canonicalizeValue,
  findDisallowedControlChar,
  normalizePathSlashes,
  type CanonicalizeResult
} from "./protocol/canonicalizer.js";
export {
  validateAndNormalizeEnvelope,
  type EnvelopeValidationResult,
  type EnvelopeValidatorOptions
} from "./protocol/envelope-validator.js";

// Inline Threat Guards
export {
  PayloadGuard,
  type GuardCheckResult
} from "./guards/payload-guard.js";
export {
  PathTraversalGuard,
  resolveLexicalPath
} from "./guards/path-traversal-guard.js";
export { CommandInjectionGuard } from "./guards/command-injection-guard.js";
export {
  SsrfGuard,
  parseIpv4,
  parseIpv6
} from "./guards/ssrf-guard.js";
export { SlidingWindowRateLimiter } from "./guards/rate-limiter.js";

// Zero-Trust RBAC Policy Engine
export {
  matchesAnyGlob,
  matchesGlob,
  matchesRole
} from "./policy/pattern-matcher.js";
export {
  PolicyEngine,
  validateArgumentConstraints,
  type DetailedPolicyDecision
} from "./policy/policy-engine.js";

// Cryptographic SHA-256 Audit Trail
export { canonicalizeJson } from "./audit/canonical-json.js";
export {
  GENESIS_PREV_HASH,
  computeAuditEntryHash,
  computeSha256Hex,
  sealAuditEntry,
  verifyAuditChain,
  type VerifyChainOptions
} from "./audit/hash-chain.js";
export {
  AuditLogger,
  REDACTED_MASK,
  RingBufferAuditSink,
  redactSensitiveArguments,
  type RecordAuditParams
} from "./audit/audit-logger.js";

// Public Type Contracts
export {
  JSONRPC_VERSION,
  JsonRpcErrorCode,
  type JsonRpcErrorCodeValue,
  type JsonRpcErrorObject,
  type JsonRpcErrorResponse,
  type JsonRpcId,
  type JsonRpcRequest,
  type JsonRpcResponse,
  type JsonRpcSuccessResponse
} from "./types/jsonrpc.js";
export type {
  ExecutionContext,
  McpOperationKind,
  McpPromptGetParams,
  McpResourceReadParams,
  McpToolCallParams,
  NormalizedMcpInvocation
} from "./types/mcp.js";
export type {
  ArgumentConstraint,
  ArgumentExpectedType,
  CommandGuardConfig,
  PathGuardConfig,
  PayloadGuardConfig,
  PolicyDecision,
  PolicyEffect,
  PolicyRule,
  RateLimitConfig,
  SsrfGuardConfig,
  WardenConfig
} from "./types/policy.js";
export type {
  AuditDecisionOutcome,
  AuditEntry,
  AuditReasonCode,
  AuditSink,
  ChainVerificationReport,
  UnsignedAuditEntry
} from "./types/audit.js";
