import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  PolicyEngine,
  matchesGlob,
  validateAndNormalizeEnvelope,
  type ExecutionContext,
  type NormalizedMcpInvocation,
  type PolicyRule
} from "../src/index.js";

function buildCall(
  toolName: string,
  args: Readonly<Record<string, unknown>> = {}
): NormalizedMcpInvocation {
  const validated = validateAndNormalizeEnvelope({
    jsonrpc: "2.0",
    id: "policy-test",
    method: "tools/call",
    params: { name: toolName, arguments: args }
  });
  if (!validated.ok) {
    throw new Error(`Unexpected envelope validation failure: ${validated.detail}`);
  }
  return validated.invocation;
}

describe("Zero-Trust RBAC PolicyEngine & O(n) Glob Matcher", () => {
  it("fails closed when no ALLOW rule matches caller roles or target", () => {
    const engine = new PolicyEngine([
      {
        id: "allow-billing-readers",
        effect: "ALLOW",
        roles: ["billing-reader"],
        operations: ["tool"],
        targets: ["billing:get_*"]
      }
    ]);

    const guestCtx: ExecutionContext = {
      principalId: "user-guest",
      roles: ["guest"]
    };

    const decision = engine.evaluate(buildCall("billing:get_invoice"), guestCtx);
    assert.equal(decision.allowed, false);
    assert.equal(decision.reasonCode, "POLICY_NO_MATCH_FAIL_CLOSED");
  });

  it("enforces Explicit DENY precedence over broad wildcard ALLOW rules", () => {
    const rules: readonly PolicyRule[] = [
      {
        id: "allow-all-db-tools",
        effect: "ALLOW",
        roles: ["engineer"],
        operations: ["tool"],
        targets: ["db:*"]
      },
      {
        id: "deny-db-drop-operations",
        effect: "DENY",
        roles: ["*"],
        operations: ["tool"],
        targets: ["db:drop_*"]
      }
    ];

    const engine = new PolicyEngine(rules);
    const engineerCtx: ExecutionContext = {
      principalId: "eng-42",
      roles: ["engineer"]
    };

    const allowedSelect = engine.evaluate(buildCall("db:select_users"), engineerCtx);
    assert.equal(allowedSelect.allowed, true);
    assert.equal(allowedSelect.matchedRuleId, "allow-all-db-tools");

    const deniedDrop = engine.evaluate(buildCall("db:drop_table"), engineerCtx);
    assert.equal(deniedDrop.allowed, false);
    assert.equal(deniedDrop.reasonCode, "POLICY_EXPLICIT_DENY");
    assert.equal(deniedDrop.matchedRuleId, "deny-db-drop-operations");
  });

  it("validates declarative argument constraints (required, enum, min/max, prefixes)", () => {
    const engine = new PolicyEngine([
      {
        id: "constrained-query",
        effect: "ALLOW",
        roles: ["analyst"],
        operations: ["tool"],
        targets: ["analytics:query"],
        argumentConstraints: {
          dataset: {
            required: true,
            type: "string",
            allowedPrefixes: ["public_", "agg_"]
          },
          limit: {
            required: true,
            type: "number",
            min: 1,
            max: 100
          },
          format: {
            type: "string",
            enum: ["json", "csv"]
          }
        }
      }
    ]);

    const analystCtx: ExecutionContext = {
      principalId: "analyst-1",
      roles: ["analyst"]
    };

    assert.equal(
      engine.evaluate(
        buildCall("analytics:query", {
          dataset: "agg_daily_revenue",
          limit: 50,
          format: "json"
        }),
        analystCtx
      ).allowed,
      true
    );

    const badPrefix = engine.evaluate(
      buildCall("analytics:query", {
        dataset: "raw_pii_users",
        limit: 50
      }),
      analystCtx
    );
    assert.equal(badPrefix.allowed, false);
    assert.equal(badPrefix.reasonCode, "ARGUMENT_CONSTRAINT_FAILED");

    const excessiveLimit = engine.evaluate(
      buildCall("analytics:query", {
        dataset: "public_events",
        limit: 5_000
      }),
      analystCtx
    );
    assert.equal(excessiveLimit.allowed, false);
    assert.equal(excessiveLimit.reasonCode, "ARGUMENT_CONSTRAINT_FAILED");
  });

  it("evaluates adversarial wildcard inputs in linear O(n) time without ReDoS", () => {
    const pathologicalPattern = "a*a*a*a*a*a*a*a*b";
    const adversarialCandidate = `${"a".repeat(2_000)}c`;

    const start = performance.now();
    const matched = matchesGlob(pathologicalPattern, adversarialCandidate);
    const elapsedMs = performance.now() - start;

    assert.equal(matched, false);
    assert.ok(
      elapsedMs < 25,
      `Expected O(n) glob matcher to finish under 25ms, took ${elapsedMs}ms`
    );
  });
});
