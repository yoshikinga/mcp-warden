import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  MCP_WARDEN_VERSION,
  runCli,
  type CliIoAdapter
} from "../src/cli/cli-runner.js";
import { McpWarden } from "../src/index.js";

interface MockCliRunResult {
  readonly exitCode: number;
  readonly out: string;
  readonly err: string;
}

async function runMockCli(
  argv: readonly string[],
  files: Readonly<Record<string, string>> = {},
  env: Readonly<Record<string, string | undefined>> = {}
): Promise<MockCliRunResult> {
  let out = "";
  let err = "";

  const io: CliIoAdapter = {
    stdout(msg: string): void {
      out += msg;
    },
    stderr(msg: string): void {
      err += msg;
    },
    async readTextFile(filePath: string): Promise<string> {
      const content = files[filePath];
      if (content === undefined) {
        throw new Error(`ENOENT: no such file '${filePath}'`);
      }
      return content;
    },
    env
  };

  const exitCode = await runCli(argv, io);
  return { exitCode, out, err };
}

describe("SecOps CLI Runner (mcp-warden v1.1.0)", () => {
  it("prints version, usage help, and rejects unknown subcommands with exit code 2", async () => {
    const ver = await runMockCli(["--version"]);
    assert.equal(ver.exitCode, 0);
    assert.equal(ver.out.trim(), `mcp-warden v${MCP_WARDEN_VERSION}`);

    const help = await runMockCli(["--help"]);
    assert.equal(help.exitCode, 0);
    assert.equal(help.out.includes("verify-audit <file.ndjson>"), true);

    const unknown = await runMockCli(["nonexistent-cmd"]);
    assert.equal(unknown.exitCode, 2);
    assert.equal(unknown.err.includes("Unknown command"), true);
  });

  it("executes built-in 6-vector cryptographic self-test in text and JSON modes", async () => {
    const textRun = await runMockCli(["self-test"]);
    assert.equal(textRun.exitCode, 0);
    assert.equal(textRun.out.includes("6/6 invariants verified"), true);

    const jsonRun = await runMockCli(["self-test", "--json"]);
    assert.equal(jsonRun.exitCode, 0);
    const parsed = JSON.parse(jsonRun.out) as Record<string, unknown>;
    assert.equal(parsed["passed"], true);
    assert.equal(parsed["version"], MCP_WARDEN_VERSION);
  });

  it("inspects inline and file-based JSON-RPC payloads across ENFORCE and DRY_RUN modes", async () => {
    const benignPayload = JSON.stringify({
      jsonrpc: "2.0",
      id: "cli-1",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/workspace/guide.md" }
      }
    });

    const okRes = await runMockCli(["inspect", benignPayload, "--json"]);
    assert.equal(okRes.exitCode, 0);
    const okJson = JSON.parse(okRes.out) as Record<string, unknown>;
    assert.equal(okJson["allowed"], true);

    const attackPayload = JSON.stringify({
      jsonrpc: "2.0",
      id: "cli-2",
      method: "tools/call",
      params: {
        name: "web:fetch",
        arguments: { url: "http://169.254.169.254/latest/meta-data/" }
      }
    });

    const enforceRes = await runMockCli(
      ["inspect", "attack.json"],
      { "attack.json": attackPayload }
    );
    assert.equal(enforceRes.exitCode, 1);
    assert.equal(enforceRes.err.includes("SSRF_BLOCKED"), true);

    const dryRunRes = await runMockCli(
      ["inspect", "attack.json", "--mode", "DRY_RUN", "--json"],
      { "attack.json": attackPayload }
    );
    assert.equal(dryRunRes.exitCode, 0);
    const dryJson = JSON.parse(dryRunRes.out) as Record<string, unknown>;
    assert.equal(dryJson["allowed"], true);
    assert.equal(dryJson["wouldDeny"], true);
  });

  it("verifies HMAC-SHA256 NDJSON audit logs via --hmac-env and detects tampering", async () => {
    const secret = "cli-production-hmac-signing-secret-2026";
    const warden = new McpWarden({
      rules: [
        {
          id: "allow-ping-tool",
          effect: "ALLOW",
          roles: ["ops"],
          operations: ["tool"],
          targets: ["sys:status"]
        }
      ],
      hmacAudit: { secretKey: secret, keyId: "prod-key-1" }
    });

    await warden.inspect(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "sys:status", arguments: {} }
      },
      { principalId: "ops-1", roles: ["ops"] }
    );

    const validNdjson = warden.exportAuditNdjson();

    const verified = await runMockCli(
      [
        "verify-audit",
        "audit.ndjson",
        "--hmac-env",
        "WARDEN_HMAC_KEY",
        "--key-id",
        "prod-key-1",
        "--expected-count",
        "1",
        "--json"
      ],
      { "audit.ndjson": validNdjson },
      { WARDEN_HMAC_KEY: secret }
    );
    assert.equal(verified.exitCode, 0);
    const verifiedJson = JSON.parse(verified.out) as Record<string, unknown>;
    assert.equal(verifiedJson["valid"], true);
    assert.equal(verifiedJson["hmacVerified"], true);

    // Wrong secret fails HMAC verification with exit code 1
    const wrongKey = await runMockCli(
      [
        "verify-audit",
        "audit.ndjson",
        "--hmac-secret",
        "wrong-secret-value",
        "--key-id",
        "prod-key-1"
      ],
      { "audit.ndjson": validNdjson }
    );
    assert.equal(wrongKey.exitCode, 1);

    // Missing file returns exit code 2
    const missingFile = await runMockCli(["verify-audit", "missing.ndjson"]);
    assert.equal(missingFile.exitCode, 2);
  });
});
