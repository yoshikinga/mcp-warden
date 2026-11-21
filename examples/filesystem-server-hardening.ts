import {
  JSONRPC_VERSION,
  McpWarden,
  createStrictProductionPreset,
  type ExecutionContext,
  type JsonRpcSuccessResponse
} from "../src/index.js";

async function runFilesystemHardeningDemo(): Promise<void> {
  // 1. Configure zero-dependency inline firewall with a strict filesystem Root Jail
  const warden = new McpWarden(
    createStrictProductionPreset({
      allowedRoots: ["/srv/agent-workspace"],
      rules: [
        {
          id: "allow-workspace-read-and-fetch",
          effect: "ALLOW",
          roles: ["coding-agent"],
          operations: ["tool"],
          targets: ["fs:read_file", "http:fetch"]
        }
      ]
    })
  );

  // 2. Wrap your existing MCP JSON-RPC request handler
  const handleMcpRequest = warden.wrap(
    async (
      _raw,
      invocation
    ): Promise<JsonRpcSuccessResponse<{ content: string }>> => ({
      jsonrpc: JSONRPC_VERSION,
      id: invocation.requestId,
      result: {
        content: `Executed '${invocation.target}' safely.`
      }
    }),
    (): ExecutionContext => ({
      principalId: "autonomous-agent-01",
      roles: ["coding-agent"],
      sessionId: "demo-session-01"
    })
  );

  // Case A: Allowed workspace read
  console.log(
    "1. Benign Read ->",
    await handleMcpRequest({
      jsonrpc: "2.0",
      id: "req-1",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/agent-workspace/README.md" }
      }
    })
  );

  // Case B: Double-encoded prompt-injection attempt targeting .env credentials
  console.log(
    "2. Double-Encoded .env Attack ->",
    await handleMcpRequest({
      jsonrpc: "2.0",
      id: "req-2",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/agent-workspace/..%252f..%252f.env" }
      }
    })
  );

  // Case C: IPv4-mapped IPv6 Cloud Metadata SSRF attempt
  console.log(
    "3. Cloud IMDS SSRF Attack ->",
    await handleMcpRequest({
      jsonrpc: "2.0",
      id: "req-3",
      method: "tools/call",
      params: {
        name: "http:fetch",
        arguments: { url: "http://[::ffff:169.254.169.254]/latest/meta-data/" }
      }
    })
  );

  // Verify tamper-evident SHA-256 audit log
  const verification = await warden.verifyAuditTrail();
  console.log("4. SHA-256 Audit Chain Verification ->", verification);
}

void runFilesystemHardeningDemo();
