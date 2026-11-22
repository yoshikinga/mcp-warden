import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  JSONRPC_VERSION,
  JsonRpcErrorCode,
  McpWarden,
  verifyAuditNdjson,
  type ExecutionContext,
  type JsonRpcErrorResponse,
  type JsonRpcSuccessResponse,
  type ViolationEvent
} from "../src/index.js";

describe("McpWarden v1.1 Full-Duplex, DRY_RUN Shadow Mode & Telemetry", () => {
  it("runs in DRY_RUN shadow mode without breaking traffic, then switches live to ENFORCE", async () => {
    const observedEvents: ViolationEvent[] = [];
    const hookErrors: unknown[] = [];

    const warden = new McpWarden(
      {
        mode: "DRY_RUN",
        rules: [
          {
            id: "allow-safe-docs",
            effect: "ALLOW",
            roles: ["agent"],
            operations: ["tool"],
            targets: ["fs:read_file"]
          }
        ],
        path: {
          allowedRoots: ["/srv/docs"]
        },
        hmacAudit: {
          secretKey: "enterprise-rollout-hmac-secret-key",
          keyId: "rollout-v1"
        }
      },
      {
        violationHooks: [
          () => {
            throw new Error("Simulated SIEM webhook network outage");
          },
          (event) => {
            observedEvents.push(event);
          }
        ],
        onHookError: (err) => {
          hookErrors.push(err);
        }
      }
    );

    const wrappedServer = warden.wrap(
      async (
        _req,
        invocation
      ): Promise<JsonRpcSuccessResponse<{ executedTarget: string }>> => ({
        jsonrpc: JSONRPC_VERSION,
        id: invocation.requestId,
        result: { executedTarget: invocation.target }
      }),
      (): ExecutionContext => ({
        principalId: "shadow-agent-01",
        roles: ["agent"],
        sessionId: "sess-shadow-1"
      })
    );

    // Attack in DRY_RUN mode: handler still executes, violation hook fires with blocked=false
    const shadowRes = await wrappedServer({
      jsonrpc: "2.0",
      id: "dry-1",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/docs/../../.env" }
      }
    });

    assert.equal("result" in shadowRes, true);
    assert.equal(hookErrors.length, 1); // Faulty hook was isolated cleanly
    assert.equal(observedEvents.length, 1);
    assert.equal(observedEvents[0]?.mode, "DRY_RUN");
    assert.equal(observedEvents[0]?.blocked, false);
    assert.equal(observedEvents[0]?.reasonCode, "SENSITIVE_FILE_BLOCKED");

    // Flip live to ENFORCE mode: exact same attack is now hard-blocked
    warden.setMode("ENFORCE");
    assert.equal(warden.getMode(), "ENFORCE");

    const enforceRes = (await wrappedServer({
      jsonrpc: "2.0",
      id: "enf-1",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/docs/../../.env" }
      }
    })) as JsonRpcErrorResponse;

    assert.equal("error" in enforceRes, true);
    assert.equal(enforceRes.error.code, JsonRpcErrorCode.ThreatDetected);

    const metrics = warden.getMetrics();
    assert.equal(metrics.totalInspected, 2);
    assert.equal(metrics.totalDryRunWouldDeny, 1);
    assert.equal(metrics.totalDenied, 1);

    // Verify exported NDJSON with HMAC-SHA256 key
    const ndjson = warden.exportAuditNdjson();
    const ndjsonCheck = await verifyAuditNdjson(ndjson, {
      hmacSecretOrKeyRing: {
        secretKey: "enterprise-rollout-hmac-secret-key",
        keyId: "rollout-v1"
      }
    });
    assert.equal(ndjsonCheck.valid, true);
    assert.equal(ndjsonCheck.checkedCount, 2);
  });

  it("enforces full-duplex egress redaction, Unicode Trojan blocking, tool pinning, and circuit breaking", async () => {
    const warden = new McpWarden({
      rules: [
        {
          id: "allow-logs-tool",
          effect: "ALLOW",
          roles: ["ops-agent"],
          operations: ["tool"],
          targets: ["logs:tail"]
        }
      ],
      egress: {
        enabled: true,
        action: "REDACT"
      },
      circuitBreaker: {
        failureThreshold: 2,
        failureWindowMs: 30_000,
        cooldownMs: 60_000
      }
    });

    const synthAwsKey = ["AK", "IA", "IOSFODNN7EXAMPLE"].join("");

    const protectedHandler = warden.wrap(
      async (
        _req,
        invocation
      ): Promise<JsonRpcSuccessResponse<{ text: string }>> => ({
        jsonrpc: JSONRPC_VERSION,
        id: invocation.requestId,
        result: {
          text: `Service booted with key ${synthAwsKey} ok.`
        }
      }),
      (): ExecutionContext => ({
        principalId: "ops-bot",
        roles: ["ops-agent"],
        sessionId: "sess-duplex-99"
      })
    );

    // 1. Valid request succeeds, and leaked AWS key in outbound response is scrubbed automatically!
    const cleanCall = await protectedHandler({
      jsonrpc: "2.0",
      id: "ok-1",
      method: "tools/call",
      params: {
        name: "logs:tail",
        arguments: { service: "payments" }
      }
    });
    assert.equal("result" in cleanCall, true);
    if ("result" in cleanCall) {
      assert.equal(cleanCall.result.text.includes(synthAwsKey), false);
      assert.equal(cleanCall.result.text.includes("[REDACTED_SECRET]"), true);
    }

    // 2. Violation #1: Unicode Bidi override attack (U+202E)
    const bidiInspect = await warden.inspect(
      {
        jsonrpc: "2.0",
        id: "atk-u1",
        method: "tools/call",
        params: {
          name: "logs:tail",
          arguments: { service: "pay\u202Ements" }
        }
      },
      { principalId: "ops-bot", roles: ["ops-agent"], sessionId: "sess-duplex-99" }
    );
    assert.equal(bidiInspect.allowed, false);
    assert.equal(bidiInspect.v11ReasonCode, "UNICODE_TROJAN_DETECTED");

    // 3. Violation #2: Unauthorized tool -> hits failureThreshold (2) and trips Circuit Breaker OPEN
    await warden.inspect(
      {
        jsonrpc: "2.0",
        id: "atk-u2",
        method: "tools/call",
        params: { name: "admin:wipe", arguments: {} }
      },
      { principalId: "ops-bot", roles: ["ops-agent"], sessionId: "sess-duplex-99" }
    );

    assert.equal(
      warden.getCircuitBreakerSnapshot("sess-duplex-99").state,
      "OPEN"
    );

    // 4. Subsequent benign call on quarantined session is immediately short-circuited
    const quarantinedCall = await warden.inspect(
      {
        jsonrpc: "2.0",
        id: "ok-blocked-by-cb",
        method: "tools/call",
        params: { name: "logs:tail", arguments: { service: "payments" } }
      },
      { principalId: "ops-bot", roles: ["ops-agent"], sessionId: "sess-duplex-99" }
    );
    assert.equal(quarantinedCall.allowed, false);
    assert.equal(quarantinedCall.v11ReasonCode, "CIRCUIT_BREAKER_OPEN");

    // 5. Inspect MCP tools/list Rug-Pull through McpWarden
    const pin1 = await warden.inspectToolsList("remote-srv", [
      { name: "logs:tail", description: "Tail service logs." }
    ]);
    assert.equal(pin1.allowed, true);

    const rugPull = await warden.inspectToolsList("remote-srv", [
      { name: "logs:tail", description: "Mutated description mid-session!" }
    ]);
    assert.equal(rugPull.allowed, false);

    const metrics = warden.getMetrics();
    assert.equal(metrics.totalEgressScrubbed, 1);
    assert.equal(metrics.totalCircuitBreakerBlocks, 1);
    assert.equal((await warden.verifyAuditTrail()).valid, true);
  });
});
