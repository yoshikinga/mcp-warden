import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { EgressSecretGuard } from "../src/guards/egress-secret-guard.js";
import { UnicodeTrojanGuard } from "../src/guards/unicode-trojan-guard.js";
import { validateAndNormalizeEnvelope } from "../src/protocol/envelope-validator.js";
import type { NormalizedMcpInvocation } from "../src/types/mcp.js";

function createToolCall(
  toolName: string,
  args: Readonly<Record<string, unknown>>
): NormalizedMcpInvocation {
  const res = validateAndNormalizeEnvelope({
    jsonrpc: "2.0",
    id: "u-test",
    method: "tools/call",
    params: { name: toolName, arguments: args }
  });
  if (!res.ok) {
    throw new Error(`Envelope setup failed: ${res.detail}`);
  }
  return res.invocation;
}

describe("UnicodeTrojanGuard & EgressSecretGuard (v1.1)", () => {
  it("UnicodeTrojanGuard permits clean international UTF-8 and blocks Bidi, ZWSP, and Plane 14 tags", () => {
    const guard = new UnicodeTrojanGuard();

    const cleanMultilingual = createToolCall("docs:search", {
      query: "Bảo mật hệ thống MCP 日本語セキュリティ café"
    });
    assert.equal(guard.check(cleanMultilingual).allowed, true);

    // CVE-2021-42574 Right-to-Left Override filename spoofing (U+202E)
    const bidiAttack = createToolCall("fs:read_file", {
      path: "/srv/workspace/notes_\u202Etxt.sh"
    });
    const bidiResult = guard.check(bidiAttack);
    assert.equal(bidiResult.allowed, false);
    if (!bidiResult.allowed) {
      assert.equal(bidiResult.reasonCode, "UNICODE_TROJAN_DETECTED");
      assert.equal(bidiResult.codePointHex, "U+202E");
    }

    // Zero-Width Space dotfile splitter (U+200B)
    const zwspAttack = createToolCall("fs:read_file", {
      path: "/srv/workspace/.\u200Benv"
    });
    const zwspResult = guard.check(zwspAttack);
    assert.equal(zwspResult.allowed, false);
    if (!zwspResult.allowed) {
      assert.equal(zwspResult.codePointHex, "U+200B");
    }

    // Astral Plane 14 Unicode Tag ASCII smuggling (U+E0001..U+E007F)
    const smuggledTags = String.fromCodePoint(0xe0001, 0xe0072, 0xe006d);
    const tagAttack = createToolCall("chat:summarize", {
      text: `Quarterly summary${smuggledTags}`
    });
    const tagResult = guard.check(tagAttack);
    assert.equal(tagResult.allowed, false);
    if (!tagResult.allowed) {
      assert.equal(tagResult.codePointHex, "U+E0001");
    }
  });

  it("EgressSecretGuard redacts multi-vendor credentials in-flight without mutating raw input", () => {
    const guard = new EgressSecretGuard({
      action: "REDACT",
      customSecretPrefixes: ["corp_live_"]
    });

    // Assemble synthetic test tokens dynamically to avoid static secret-scanner false alarms
    const synthAws = ["AK", "IA", "IOSFODNN7EXAMPLE"].join("");
    const synthGithub = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("");
    const synthAnthropic = ["sk", "-ant-", "api03-", "z".repeat(24)].join("");
    const synthStripe = ["sk", "_live_", "9".repeat(24)].join("");
    const synthJwt = [
      "eyJhbGciOiJIUzI1NiJ9",
      "eyJzdWIiOiJhZG1pbiJ9",
      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ].join(".");
    const synthPem = [
      "-----BEGIN ",
      "RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtestpayload\n-----END ",
      "RSA PRIVATE KEY-----"
    ].join("");
    const synthDbUri = ["postgres://dbadmin:", "Sup3rS3cr3t!", "@10.0.0.12:5432/prod"].join("");
    const synthCustom = ["corp_live_", "tok987654321"].join("");

    const originalResponse = {
      jsonrpc: "2.0",
      id: 99,
      result: {
        logSnippet: `AWS=${synthAws} GH=${synthGithub} ANT=${synthAnthropic} STRIPE=${synthStripe}`,
        authTrace: `Token: ${synthJwt} | Custom: ${synthCustom}`,
        conn: synthDbUri,
        certDump: synthPem
      }
    };

    const outcome = guard.inspect(originalResponse);
    assert.equal(outcome.allowed, true);
    assert.equal(outcome.mutated, true);
    assert.equal(outcome.reasonCode, "EGRESS_SECRET_REDACTED");
    assert.equal(outcome.findings.length, 8);

    // Caller object remains untouched
    assert.equal(originalResponse.result.conn.includes("Sup3rS3cr3t!"), true);

    // Sanitized payload masks every credential while preserving non-secret context
    const sanitizedText = JSON.stringify(outcome.sanitizedPayload);
    assert.equal(sanitizedText.includes(synthAws), false);
    assert.equal(sanitizedText.includes(synthGithub), false);
    assert.equal(sanitizedText.includes(synthAnthropic), false);
    assert.equal(sanitizedText.includes(synthStripe), false);
    assert.equal(sanitizedText.includes(synthJwt), false);
    assert.equal(sanitizedText.includes("MIIEpAIBAAKCAQEAtestpayload"), false);
    assert.equal(sanitizedText.includes("Sup3rS3cr3t!"), false);
    assert.equal(sanitizedText.includes(synthCustom), false);
    assert.equal(
      outcome.sanitizedPayload.result.conn,
      "postgres://dbadmin:[REDACTED_SECRET]@10.0.0.12:5432/prod"
    );

    // Previews never expose secret tails
    for (const finding of outcome.findings) {
      assert.equal(finding.preview.endsWith("****"), true);
    }
  });

  it("EgressSecretGuard rejects responses outright when configured with action: BLOCK", () => {
    const blockingGuard = new EgressSecretGuard({ action: "BLOCK" });
    const leakedKey = ["AK", "IA", "1111222233334444"].join("");

    const result = blockingGuard.inspect({
      content: [{ type: "text", text: `Found key ${leakedKey} in config` }]
    });

    assert.equal(result.allowed, false);
    assert.equal(result.reasonCode, "EGRESS_SECRET_BLOCKED");
    assert.equal(result.findings.length, 1);
  });
});
