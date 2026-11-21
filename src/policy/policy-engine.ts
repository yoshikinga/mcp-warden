import type { AuditReasonCode } from "../types/audit.js";
import type { ExecutionContext, NormalizedMcpInvocation } from "../types/mcp.js";
import type {
  ArgumentConstraint,
  ArgumentExpectedType,
  PolicyDecision,
  PolicyRule
} from "../types/policy.js";
import { matchesAnyGlob, matchesRole } from "./pattern-matcher.js";

/**
 * Extended RBAC policy decision carrying a standardized audit reason code.
 */
export interface DetailedPolicyDecision extends PolicyDecision {
  readonly reasonCode: Extract<
    AuditReasonCode,
    | "ALLOWED_BY_POLICY"
    | "POLICY_EXPLICIT_DENY"
    | "POLICY_NO_MATCH_FAIL_CLOSED"
    | "ARGUMENT_CONSTRAINT_FAILED"
  >;
}

type ConstraintValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

function detectArgumentType(value: unknown): ArgumentExpectedType | "invalid" {
  if (Array.isArray(value)) {
    return "array";
  }
  if (value === null) {
    return "invalid";
  }
  switch (typeof value) {
    case "string":
      return "string";
    case "boolean":
      return "boolean";
    case "number":
      return Number.isFinite(value) ? "number" : "invalid";
    case "object":
      return "object";
    default:
      return "invalid";
  }
}

/**
 * Validates canonicalized tool/prompt arguments against declarative parameter constraints.
 */
export function validateArgumentConstraints(
  args: Readonly<Record<string, unknown>>,
  constraints: Readonly<Record<string, ArgumentConstraint>>
): ConstraintValidationResult {
  for (const [argName, constraint] of Object.entries(constraints)) {
    const value = args[argName];

    if (value === undefined || value === null) {
      if (constraint.required === true) {
        return {
          ok: false,
          reason: `Missing required argument '${argName}'.`
        };
      }
      continue;
    }

    if (constraint.type !== undefined) {
      const actualType = detectArgumentType(value);
      if (actualType !== constraint.type) {
        return {
          ok: false,
          reason: `Argument '${argName}' expected type '${constraint.type}', received '${actualType}'.`
        };
      }
    }

    if (constraint.enum !== undefined) {
      if (
        (typeof value !== "string" &&
          typeof value !== "number" &&
          typeof value !== "boolean") ||
        !constraint.enum.includes(value)
      ) {
        return {
          ok: false,
          reason: `Argument '${argName}' value is not in allowed enum set.`
        };
      }
    }

    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        return {
          ok: false,
          reason: `Argument '${argName}' must be a finite number.`
        };
      }
      if (constraint.min !== undefined && value < constraint.min) {
        return {
          ok: false,
          reason: `Argument '${argName}' (${value}) is below minimum (${constraint.min}).`
        };
      }
      if (constraint.max !== undefined && value > constraint.max) {
        return {
          ok: false,
          reason: `Argument '${argName}' (${value}) exceeds maximum (${constraint.max}).`
        };
      }
    }

    if (typeof value === "string") {
      if (constraint.maxLength !== undefined && value.length > constraint.maxLength) {
        return {
          ok: false,
          reason: `Argument '${argName}' length (${value.length}) exceeds maxLength (${constraint.maxLength}).`
        };
      }
      if (
        constraint.allowedPrefixes !== undefined &&
        constraint.allowedPrefixes.length > 0
      ) {
        const hasAllowedPrefix = constraint.allowedPrefixes.some((prefix) =>
          value.startsWith(prefix)
        );
        if (!hasAllowedPrefix) {
          return {
            ok: false,
            reason: `Argument '${argName}' does not start with any allowed prefix.`
          };
        }
      }
    }
  }

  return { ok: true };
}

/**
 * Deterministic Zero-Trust RBAC Policy Engine.
 * Evaluation order:
 * 1. Explicit DENY rules always override ALLOW rules.
 * 2. Matching ALLOW rules must satisfy all configured argumentConstraints.
 * 3. Any unmatched request is rejected (Fail-Closed).
 */
export class PolicyEngine {
  private readonly rules: readonly PolicyRule[];

  public constructor(rules: readonly PolicyRule[]) {
    this.rules = [...rules];
  }

  public evaluate(
    invocation: NormalizedMcpInvocation,
    context: ExecutionContext
  ): DetailedPolicyDecision {
    const candidateRules: PolicyRule[] = [];

    for (let i = 0; i < this.rules.length; i += 1) {
      const rule = this.rules[i];
      if (rule === undefined) {
        continue;
      }

      if (!matchesRole(rule.roles, context.roles)) {
        continue;
      }

      if (
        rule.operations !== undefined &&
        !rule.operations.includes(invocation.operationKind)
      ) {
        continue;
      }

      if (!matchesAnyGlob(rule.targets, invocation.target)) {
        continue;
      }

      candidateRules.push(rule);
    }

    // Pass 1: Explicit DENY precedence
    for (let i = 0; i < candidateRules.length; i += 1) {
      const rule = candidateRules[i];
      if (rule === undefined || rule.effect !== "DENY") {
        continue;
      }

      if (rule.argumentConstraints === undefined) {
        return {
          allowed: false,
          matchedRuleId: rule.id,
          reasonCode: "POLICY_EXPLICIT_DENY",
          reason: `Explicitly denied by policy rule '${rule.id}' for target '${invocation.target}'.`
        };
      }

      const denyCondition = validateArgumentConstraints(
        invocation.canonicalArguments,
        rule.argumentConstraints
      );
      if (denyCondition.ok) {
        return {
          allowed: false,
          matchedRuleId: rule.id,
          reasonCode: "POLICY_EXPLICIT_DENY",
          reason: `Explicitly denied by conditional policy rule '${rule.id}'.`
        };
      }
    }

    // Pass 2: Explicit ALLOW evaluation with parameter constraints
    let firstConstraintFailure: {
      readonly ruleId: string;
      readonly reason: string;
    } | null = null;

    for (let i = 0; i < candidateRules.length; i += 1) {
      const rule = candidateRules[i];
      if (rule === undefined || rule.effect !== "ALLOW") {
        continue;
      }

      if (rule.argumentConstraints !== undefined) {
        const check = validateArgumentConstraints(
          invocation.canonicalArguments,
          rule.argumentConstraints
        );
        if (!check.ok) {
          if (firstConstraintFailure === null) {
            firstConstraintFailure = {
              ruleId: rule.id,
              reason: `Rule '${rule.id}' constraint failed: ${check.reason}`
            };
          }
          continue;
        }
      }

      return {
        allowed: true,
        matchedRuleId: rule.id,
        reasonCode: "ALLOWED_BY_POLICY",
        reason: `Allowed by policy rule '${rule.id}'.`
      };
    }

    if (firstConstraintFailure !== null) {
      return {
        allowed: false,
        matchedRuleId: firstConstraintFailure.ruleId,
        reasonCode: "ARGUMENT_CONSTRAINT_FAILED",
        reason: firstConstraintFailure.reason
      };
    }

    return {
      allowed: false,
      matchedRuleId: null,
      reasonCode: "POLICY_NO_MATCH_FAIL_CLOSED",
      reason: `No matching ALLOW rule for principal '${context.principalId}' on '${invocation.target}' (fail-closed).`
    };
  }
}
