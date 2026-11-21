import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  JSONRPC_VERSION,
  JsonRpcErrorCode,
  McpWarden,
  WardenError,
  createReadOnlyAgentPreset,
  createStrictProductionPreset,
  type ExecutionContext,
  type JsonRpcErrorResponse,
  type JsonRpcSuccessResponse
} from "../src/index.js";

describe("McpWarden End-to-End Integration", () => {
  it("wraps MCP server handlers, blocks attacks, sanitizes client errors, and seals audit logs", async () => {
    const config = createStrictProductionPreset({
      allowedRoots: ["/srv/mcp-sandbox"],
      rules: [
        {
          id: "allow-sandbox-fs-and-web",
          effect: "ALLOW",
          roles: ["support-agent"],
          operations: ["tool"],
          targets: ["fs:read_file", "web:fetch"]
        }
      ]
    });

    const warden = new McpWarden(config);

    const protectedHandler = warden.wrap(
      async (
        _rawRequest: unknown,
        invocation
      ): Promise<JsonRpcSuccessResponse<{ ok: boolean; target: string; rawPath: unknown }>> => ({
        jsonrpc: JSONRPC_VERSION,
        id: invocation.requestId,
        result: {
          ok: true,
          target: invocation.target,
          rawPath: invocation.rawArguments["path"]
        }
      }),
      (): ExecutionContext => ({
        principalId: "agent-prod-01",
        roles: ["support-agent"],
        sessionId: "sess-e2e-1"
      })
    );

    // 1. Standard MCP discovery passes without extra rules
    const initResponse = await protectedHandler({
      jsonrpc: "2.0",
      id: "init-1",
      method: "initialize",
      params: { clientInfo: { name: "claude-desktop" } }
    });
    assert.equal("result" in initResponse, true);

    // 2. Legitimate sandboxed file read succeeds and preserves rawArguments
    const validRead = await protectedHandler({
      jsonrpc: "2.0",
      id: "read-1",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/mcp-sandbox/manual%20v1.md" }
      }
    });
    assert.equal("result" in validRead, true);
    if ("result" in validRead) {
      assert.equal(validRead.result.rawPath, "/srv/mcp-sandbox/manual%20v1.md");
    }

    // 3. Double-encoded .env exfiltration is blocked with sanitized external error
    const blockedEnv = (await protectedHandler({
      jsonrpc: "2.0",
      id: "atk-env",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/mcp-sandbox/..%252f..%252f.env" }
      }
    })) as JsonRpcErrorResponse;

    assert.equal("error" in blockedEnv, true);
    assert.equal(blockedEnv.error.code, JsonRpcErrorCode.ThreatDetected);
    // Ensure internal server directory root is NEVER leaked in client-facing error text
    assert.equal(blockedEnv.error.message.includes("/srv/mcp-sandbox"), false);
    assert.equal(blockedEnv.error.data?.["reasonCode"], "SENSITIVE_FILE_BLOCKED");
    assert.equal(typeof blockedEnv.error.data?.["auditHash"], "string");

    // 4. Verify complete cryptographic SHA-256 audit chain integrity
    const chainReport = await warden.verifyAuditTrail();
    assert.equal(chainReport.valid, true);
    assert.equal(chainReport.checkedCount, 3);
  });

  it("enforces createReadOnlyAgentPreset via assertAllowed()", async () => {
    const warden = new McpWarden(
      createReadOnlyAgentPreset({
        allowedRoots: ["/var/reports"]
      })
    );

    const ctx: ExecutionContext = {
      principalId: "readonly-copilot",
      roles: ["observer"]
    };

    const allowedInvocation = await warden.assertAllowed(
      {
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: {
          name: "fs:read_summary",
          arguments: { path: "/var/reports/daily.json" }
        }
      },
      ctx
    );
    assert.equal(allowedInvocation.target, "fs:read_summary");

    await assert.rejects(
      async () =>
        warden.assertAllowed(
          {
            jsonrpc: "2.0",
            id: 11,
            method: "tools/call",
            params: {
              name: "fs:delete_summary",
              arguments: { path: "/var/reports/daily.json" }
            }
          },
          ctx
        ),
      (err: unknown) => {
        assert.ok(err instanceof WardenError);
        assert.equal(err.reasonCode, "POLICY_EXPLICIT_DENY");
        assert.equal(err.jsonRpcCode, JsonRpcErrorCode.PolicyDenied);
        return true;
      }
    );
  });
});
