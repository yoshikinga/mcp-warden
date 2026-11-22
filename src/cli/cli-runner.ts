import { verifyAuditNdjson } from "../audit/ndjson-codec.js";
import { createStrictProductionPreset } from "../presets/security-presets.js";
import { JSONRPC_VERSION } from "../types/jsonrpc.js";
import type { ExecutionContext } from "../types/mcp.js";
import type { EnforcementMode } from "../types/v1-1.js";
import { McpWarden } from "../warden.js";

/**
 * Current semantic version of the mcp-warden CLI and runtime kernel.
 */
export const MCP_WARDEN_VERSION = "1.1.0";

/**
 * Runtime-agnostic I/O adapter enabling deterministic CLI testing without console globals.
 */
export interface CliIoAdapter {
  stdout(message: string): void;
  stderr(message: string): void;
  readTextFile(filePath: string): Promise<string>;
  readonly env: Readonly<Record<string, string | undefined>>;
}

interface ParsedCliFlags {
  readonly positionals: readonly string[];
  readonly flags: ReadonlyMap<string, string | boolean>;
}

interface SelfTestCheckOutcome {
  readonly name: string;
  readonly passed: boolean;
  readonly detail: string;
}

const HELP_TEXT = `mcp-warden v${MCP_WARDEN_VERSION} — Zero-Dependency MCP Security Firewall & Audit CLI

Usage:
  mcp-warden <command> [options]

Commands:
  verify-audit <file.ndjson>   Verify SHA-256 links and optional HMAC-SHA256 signatures
  inspect <payload-or-file>    Run inline 6-stage + v1.1 inspection against a JSON-RPC payload
  self-test                    Execute built-in 6-vector security & HMAC self-diagnostic
  version                      Print CLI version
  help                         Show this help message

Options for verify-audit:
  --hmac-secret <secret>       Verify HMAC-SHA256 tags using an explicit secret string
  --hmac-env <ENV_VAR>         Read HMAC-SHA256 secret key from an environment variable
  --key-id <id>                Expected HMAC key identifier (default: "default")
  --expected-count <n>         Assert exact entry count to detect tail-truncation
  --expected-last-hash <hex>   Assert exact 64-char hex digest of the final entry
  --allow-subchain             Allow verifying rotated log windows starting above sequence 0
  --json                       Emit machine-readable JSON verification output

Options for inspect:
  --principal <id>             Caller principal ID (default: "cli-inspector")
  --role <role>                Caller RBAC role (default: "operator")
  --allowed-root <path>        Permitted filesystem root jail (default: "/srv/workspace")
  --mode <ENFORCE|DRY_RUN>     Gateway operating mode (default: "ENFORCE")
  --json                       Emit machine-readable JSON inspection output
`;

const BOOLEAN_FLAGS: ReadonlySet<string> = new Set([
  "--help",
  "-h",
  "--version",
  "-v",
  "--json",
  "--allow-subchain"
]);

function parseCliArguments(argv: readonly string[]): ParsedCliFlags {
  const positionals: string[] = [];
  const flags = new Map<string, string | boolean>();

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === undefined) {
      continue;
    }

    if (!token.startsWith("-")) {
      positionals.push(token);
      continue;
    }

    if (BOOLEAN_FLAGS.has(token)) {
      flags.set(token, true);
      continue;
    }

    const eqIdx = token.indexOf("=");
    if (eqIdx !== -1) {
      flags.set(token.slice(0, eqIdx), token.slice(eqIdx + 1));
      continue;
    }

    const nextToken = argv[i + 1];
    if (nextToken !== undefined && !nextToken.startsWith("-")) {
      flags.set(token, nextToken);
      i += 1;
    } else {
      flags.set(token, true);
    }
  }

  return { positionals, flags };
}

function getStringFlag(
  flags: ReadonlyMap<string, string | boolean>,
  name: string
): string | undefined {
  const raw = flags.get(name);
  return typeof raw === "string" ? raw : undefined;
}

function getBooleanFlag(
  flags: ReadonlyMap<string, string | boolean>,
  name: string
): boolean {
  return flags.get(name) === true;
}

async function handleVerifyAudit(
  parsed: ParsedCliFlags,
  io: CliIoAdapter
): Promise<number> {
  const filePath = parsed.positionals[1];
  const jsonOutput = getBooleanFlag(parsed.flags, "--json");

  if (filePath === undefined || filePath.trim().length === 0) {
    io.stderr("Error: Missing <file.ndjson> path for 'verify-audit'.\n");
    return 2;
  }

  let ndjsonContent: string;
  try {
    ndjsonContent = await io.readTextFile(filePath);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : "Unable to read file.";
    io.stderr(`Error reading '${filePath}': ${msg}\n`);
    return 2;
  }

  const directSecret = getStringFlag(parsed.flags, "--hmac-secret");
  const secretEnvVar = getStringFlag(parsed.flags, "--hmac-env");
  const keyId = getStringFlag(parsed.flags, "--key-id") ?? "default";

  let resolvedHmacSecret: string | undefined = directSecret;
  if (secretEnvVar !== undefined) {
    const envVal = io.env[secretEnvVar];
    if (envVal === undefined || envVal.trim().length === 0) {
      io.stderr(
        `Error: Environment variable '${secretEnvVar}' for --hmac-env is unset or empty.\n`
      );
      return 2;
    }
    resolvedHmacSecret = envVal;
  }

  const expectedCountRaw = getStringFlag(parsed.flags, "--expected-count");
  let expectedCount: number | undefined;
  if (expectedCountRaw !== undefined) {
    const parsedNum = Number(expectedCountRaw);
    if (!Number.isInteger(parsedNum) || parsedNum < 0) {
      io.stderr("Error: --expected-count must be a non-negative integer.\n");
      return 2;
    }
    expectedCount = parsedNum;
  }

  const expectedLastHash = getStringFlag(parsed.flags, "--expected-last-hash");
  const allowSubchain = getBooleanFlag(parsed.flags, "--allow-subchain");

  const report = await verifyAuditNdjson(ndjsonContent, {
    allowSubchain,
    ...(expectedCount !== undefined ? { expectedCount } : {}),
    ...(expectedLastHash !== undefined ? { expectedLastHash } : {}),
    ...(resolvedHmacSecret !== undefined
      ? { hmacSecretOrKeyRing: { secretKey: resolvedHmacSecret, keyId } }
      : {})
  });

  if (jsonOutput) {
    io.stdout(
      `${JSON.stringify({
        file: filePath,
        hmacVerified: resolvedHmacSecret !== undefined,
        ...report
      })}\n`
    );
  } else if (report.valid) {
    const modeLabel =
      resolvedHmacSecret !== undefined ? "SHA-256 + HMAC-SHA256" : "SHA-256";
    io.stdout(
      `PASS: Verified ${report.checkedCount} audit record(s) in '${filePath}' (${modeLabel} intact).\n`
    );
  } else {
    io.stderr(
      `FAIL: Audit chain verification failed at sequence ${String(report.brokenAtSequence)}: ${report.reason ?? "Unknown error"}\n`
    );
  }

  return report.valid ? 0 : 1;
}

async function handleInspect(
  parsed: ParsedCliFlags,
  io: CliIoAdapter
): Promise<number> {
  const inputTarget = parsed.positionals[1];
  const jsonOutput = getBooleanFlag(parsed.flags, "--json");

  if (inputTarget === undefined || inputTarget.trim().length === 0) {
    io.stderr("Error: Missing <payload-or-file> argument for 'inspect'.\n");
    return 2;
  }

  let rawPayloadText = inputTarget.trim();
  if (!rawPayloadText.startsWith("{") && !rawPayloadText.startsWith("[")) {
    try {
      rawPayloadText = await io.readTextFile(inputTarget);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unable to read payload file.";
      io.stderr(`Error reading '${inputTarget}': ${msg}\n`);
      return 2;
    }
  }

  const principalId = getStringFlag(parsed.flags, "--principal") ?? "cli-inspector";
  const role = getStringFlag(parsed.flags, "--role") ?? "operator";
  const allowedRoot =
    getStringFlag(parsed.flags, "--allowed-root") ?? "/srv/workspace";
  const rawMode = getStringFlag(parsed.flags, "--mode") ?? "ENFORCE";

  if (rawMode !== "ENFORCE" && rawMode !== "DRY_RUN") {
    io.stderr("Error: --mode must be either 'ENFORCE' or 'DRY_RUN'.\n");
    return 2;
  }
  const mode: EnforcementMode = rawMode;

  const basePreset = createStrictProductionPreset({
    allowedRoots: [allowedRoot],
    rules: [
      {
        id: "cli-default-allow-role-tools",
        effect: "ALLOW",
        roles: [role],
        operations: ["tool", "resource", "prompt"],
        targets: ["*"]
      }
    ]
  });

  const warden = new McpWarden({
    ...basePreset,
    mode
  });

  const context: ExecutionContext = {
    principalId,
    roles: [role],
    sessionId: "cli-inspect-session"
  };

  const result = await warden.inspect(rawPayloadText, context);

  if (jsonOutput) {
    io.stdout(
      `${JSON.stringify({
        allowed: result.allowed,
        mode: result.mode,
        wouldDeny: result.wouldDeny,
        reasonCode: result.auditEntry.reasonCode,
        v11ReasonCode: result.v11ReasonCode,
        target: result.auditEntry.target,
        auditHash: result.auditEntry.hash
      })}\n`
    );
  } else if (result.allowed) {
    io.stdout(
      `ALLOW [${result.mode}] target='${result.auditEntry.target}' reason='${result.auditEntry.reasonCode}' hash=${result.auditEntry.hash}\n`
    );
  } else {
    io.stderr(
      `DENY [${result.mode}] target='${result.auditEntry.target}' reason='${result.v11ReasonCode ?? result.auditEntry.reasonCode}' hash=${result.auditEntry.hash}\n`
    );
  }

  return result.allowed ? 0 : 1;
}

async function handleSelfTest(
  parsed: ParsedCliFlags,
  io: CliIoAdapter
): Promise<number> {
  const jsonOutput = getBooleanFlag(parsed.flags, "--json");
  const hmacSecret = "mcp-warden-cli-selftest-hmac-secret-2026";

  const basePreset = createStrictProductionPreset({
    allowedRoots: ["/srv/selftest"],
    rules: [
      {
        id: "selftest-allow-ops",
        effect: "ALLOW",
        roles: ["selftest-role"],
        operations: ["tool"],
        targets: ["fs:read_file", "git:checkout", "web:fetch", "logs:tail"]
      }
    ]
  });

  const warden = new McpWarden({
    ...basePreset,
    egress: { enabled: true, action: "REDACT" },
    hmacAudit: { secretKey: hmacSecret, keyId: "selftest-k1" }
  });

  const ctx: ExecutionContext = {
    principalId: "selftest-principal",
    roles: ["selftest-role"],
    sessionId: "selftest-session"
  };

  const checks: SelfTestCheckOutcome[] = [];

  const c1 = await warden.inspect(
    {
      jsonrpc: JSONRPC_VERSION,
      id: 1,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/selftest/README.md" }
      }
    },
    ctx
  );
  checks.push({
    name: "allow-benign-workspace-read",
    passed: c1.allowed && c1.auditEntry.reasonCode === "ALLOWED_BY_POLICY",
    detail: c1.auditEntry.reasonCode
  });

  const c2 = await warden.inspect(
    {
      jsonrpc: JSONRPC_VERSION,
      id: 2,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/selftest/..%252f..%252f.env" }
      }
    },
    ctx
  );
  checks.push({
    name: "block-double-encoded-dotenv",
    passed: !c2.allowed && c2.auditEntry.reasonCode === "SENSITIVE_FILE_BLOCKED",
    detail: c2.auditEntry.reasonCode
  });

  const c3 = await warden.inspect(
    {
      jsonrpc: JSONRPC_VERSION,
      id: 3,
      method: "tools/call",
      params: {
        name: "git:checkout",
        arguments: { branch: "$" + "(whoami)" }
      }
    },
    ctx
  );
  checks.push({
    name: "block-command-subshell-injection",
    passed:
      !c3.allowed && c3.auditEntry.reasonCode === "COMMAND_INJECTION_BLOCKED",
    detail: c3.auditEntry.reasonCode
  });

  const c4 = await warden.inspect(
    {
      jsonrpc: JSONRPC_VERSION,
      id: 4,
      method: "tools/call",
      params: {
        name: "web:fetch",
        arguments: { url: "http://[::ffff:169.254.169.254]/latest/meta-data/" }
      }
    },
    ctx
  );
  checks.push({
    name: "block-ipv6-mapped-imds-ssrf",
    passed: !c4.allowed && c4.auditEntry.reasonCode === "SSRF_BLOCKED",
    detail: c4.auditEntry.reasonCode
  });

  const c5 = await warden.inspect(
    {
      jsonrpc: JSONRPC_VERSION,
      id: 5,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/selftest/report_\u202Etxt.sh" }
      }
    },
    ctx
  );
  checks.push({
    name: "block-unicode-trojan-bidi",
    passed: !c5.allowed && c5.v11ReasonCode === "UNICODE_TROJAN_DETECTED",
    detail: c5.v11ReasonCode ?? c5.auditEntry.reasonCode
  });

  const synthAws = ["AK", "IA", "IOSFODNN7EXAMPLE"].join("");
  const egressCheck = await warden.inspectResponse<{ readonly log: string }>(
    { log: `Credential=${synthAws}` },
    ctx,
    "logs:tail",
    6
  );
  const ndjsonVerify = await verifyAuditNdjson(warden.exportAuditNdjson(), {
    hmacSecretOrKeyRing: { secretKey: hmacSecret, keyId: "selftest-k1" }
  });

  checks.push({
    name: "egress-redact-and-hmac-ndjson-verify",
    passed:
      egressCheck.mutated &&
      !egressCheck.sanitizedPayload.log.includes(synthAws) &&
      ndjsonVerify.valid &&
      ndjsonVerify.checkedCount === 6,
    detail: `egressMutated=${String(egressCheck.mutated)},auditValid=${String(ndjsonVerify.valid)}`
  });

  const allPassed = checks.every((c) => c.passed);

  if (jsonOutput) {
    io.stdout(
      `${JSON.stringify({
        version: MCP_WARDEN_VERSION,
        passed: allPassed,
        checks
      })}\n`
    );
  } else {
    for (let i = 0; i < checks.length; i += 1) {
      const item = checks[i];
      if (item !== undefined) {
        const mark = item.passed ? "PASS" : "FAIL";
        io.stdout(`[${mark}] ${item.name} (${item.detail})\n`);
      }
    }
    io.stdout(
      allPassed
        ? `mcp-warden v${MCP_WARDEN_VERSION} self-test succeeded (6/6 invariants verified).\n`
        : `mcp-warden v${MCP_WARDEN_VERSION} self-test FAILED.\n`
    );
  }

  return allPassed ? 0 : 1;
}

/**
 * Executes the mcp-warden SecOps CLI and returns a POSIX exit code (0 = pass, 1 = violation/fail, 2 = usage error).
 */
export async function runCli(
  argv: readonly string[],
  io: CliIoAdapter
): Promise<number> {
  const parsed = parseCliArguments(argv);

  if (
    getBooleanFlag(parsed.flags, "--version") ||
    getBooleanFlag(parsed.flags, "-v") ||
    parsed.positionals[0] === "version"
  ) {
    io.stdout(`mcp-warden v${MCP_WARDEN_VERSION}\n`);
    return 0;
  }

  if (
    parsed.positionals.length === 0 ||
    getBooleanFlag(parsed.flags, "--help") ||
    getBooleanFlag(parsed.flags, "-h") ||
    parsed.positionals[0] === "help"
  ) {
    io.stdout(HELP_TEXT);
    return 0;
  }

  const command = parsed.positionals[0];
  switch (command) {
    case "verify-audit":
      return handleVerifyAudit(parsed, io);
    case "inspect":
      return handleInspect(parsed, io);
    case "self-test":
      return handleSelfTest(parsed, io);
    default:
      io.stderr(
        `Error: Unknown command '${String(command)}'. Run 'mcp-warden --help' for usage.\n`
      );
      return 2;
  }
}
