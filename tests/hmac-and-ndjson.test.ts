import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AuditLogger,
  GENESIS_PREV_HASH,
  HmacAuditSigner,
  NdjsonAuditSink,
  RingBufferAuditSink,
  parseAuditNdjson,
  sealAuditEntry,
  verifyAuditChain,
  verifyAuditNdjson,
  verifySignedAuditChain,
  type SignedAuditEntry
} from "../src/index.js";

describe("HMAC-SHA256 Audit Signing & SIEM NDJSON Codec (v1.1)", () => {
  it("defeats full-chain Genesis SHA-256 rewrite attacks when protected by HMAC-SHA256", async () => {
    const signingConfig = {
      secretKey: "warden-prod-hmac-signing-key-2026",
      keyId: "prod-k1"
    };
    const signer = new HmacAuditSigner(signingConfig);
    const signedEntries: SignedAuditEntry[] = [];

    const ringSink = new RingBufferAuditSink(10);
    const logger = new AuditLogger({
      sinks: [
        {
          write: async (sealed) => {
            const signed = await signer.signEntry(sealed);
            ringSink.write(signed);
            signedEntries.push(signed);
          }
        }
      ]
    });

    await logger.record({
      requestId: "r-1",
      principalId: "agent-01",
      method: "tools/call",
      operationKind: "tool",
      target: "fs:read_file",
      decision: "DENY",
      reasonCode: "SENSITIVE_FILE_BLOCKED",
      matchedRuleId: null,
      detail: "Blocked .env exfiltration",
      latencyMs: 0.21,
      argumentsToLog: { path: ".env" }
    });

    await logger.record({
      requestId: "r-2",
      principalId: "agent-01",
      method: "tools/call",
      operationKind: "tool",
      target: "web:fetch",
      decision: "DENY",
      reasonCode: "SSRF_BLOCKED",
      matchedRuleId: null,
      detail: "Blocked cloud metadata SSRF",
      latencyMs: 0.19,
      argumentsToLog: { url: "http://169.254.169.254" }
    });

    // Legitimate HMAC verification passes
    const validReport = await verifySignedAuditChain(signedEntries, signingConfig, {
      expectedCount: 2,
      expectedLastHash: signedEntries[1]?.hash ?? ""
    });
    assert.equal(validReport.valid, true);
    assert.equal(validReport.checkedCount, 2);

    // Simulate sophisticated disk attacker who rewrites sequence 0 & 1 from scratch
    // and recomputes valid unkeyed SHA-256 hashes (without knowing secretKey):
    const forgedZero = await sealAuditEntry({
      sequence: 0,
      timestamp: new Date().toISOString(),
      requestId: "r-1",
      principalId: "agent-01",
      sessionId: null,
      method: "tools/call",
      operationKind: "tool",
      target: "fs:read_file",
      decision: "ALLOW",
      reasonCode: "ALLOWED_BY_POLICY",
      matchedRuleId: "forged-rule",
      detail: "Forged allow record",
      latencyMs: 0.1,
      redactedArguments: { path: "README.md" },
      prevHash: GENESIS_PREV_HASH
    });

    const forgedSignedZero: SignedAuditEntry = {
      ...forgedZero,
      hmacKeyId: "prod-k1",
      hmacSignature: signedEntries[0]?.hmacSignature ?? "0".repeat(64)
    };

    // Unkeyed SHA-256 verifier alone would accept forgedZero, but HMAC verifier catches it!
    assert.equal((await verifyAuditChain([forgedSignedZero])).valid, true);
    const hmacCheck = await verifySignedAuditChain(
      [forgedSignedZero],
      signingConfig
    );
    assert.equal(hmacCheck.valid, false);
    assert.equal(hmacCheck.brokenAtSequence, 0);
  });

  it("supports zero-downtime HMAC key rotation via key-ring dictionaries", async () => {
    const keyRing: Readonly<Record<string, string>> = {
      "key-2026-q3": "old-quarter-hmac-secret-value-001",
      "key-2026-q4": "new-quarter-hmac-secret-value-002"
    };

    const signerQ3 = new HmacAuditSigner({
      secretKey: keyRing["key-2026-q3"] ?? "",
      keyId: "key-2026-q3"
    });
    const signerQ4 = new HmacAuditSigner({
      secretKey: keyRing["key-2026-q4"] ?? "",
      keyId: "key-2026-q4"
    });

    const entry0 = await sealAuditEntry({
      sequence: 0,
      timestamp: "2026-09-30T23:59:59.000Z",
      requestId: 1,
      principalId: "svc-a",
      sessionId: null,
      method: "ping",
      operationKind: "lifecycle",
      target: "ping",
      decision: "ALLOW",
      reasonCode: "ALLOWED_DISCOVERY",
      matchedRuleId: null,
      detail: "ok",
      latencyMs: 0.05,
      redactedArguments: {},
      prevHash: GENESIS_PREV_HASH
    });

    const signed0 = await signerQ3.signEntry(entry0);

    const entry1 = await sealAuditEntry({
      sequence: 1,
      timestamp: "2026-10-01T00:00:01.000Z",
      requestId: 2,
      principalId: "svc-a",
      sessionId: null,
      method: "ping",
      operationKind: "lifecycle",
      target: "ping",
      decision: "ALLOW",
      reasonCode: "ALLOWED_DISCOVERY",
      matchedRuleId: null,
      detail: "ok",
      latencyMs: 0.05,
      redactedArguments: {},
      prevHash: signed0.hash
    });

    const signed1 = await signerQ4.signEntry(entry1);

    const rotatedReport = await verifySignedAuditChain(
      [signed0, signed1],
      keyRing
    );
    assert.equal(rotatedReport.valid, true);
    assert.equal(rotatedReport.checkedCount, 2);

    // Tail truncation caught when expectedCount = 3
    const truncatedReport = await verifySignedAuditChain(
      [signed0, signed1],
      keyRing,
      { expectedCount: 3 }
    );
    assert.equal(truncatedReport.valid, false);
  });

  it("serializes, parses, and verifies NDJSON streams via NdjsonAuditSink", async () => {
    const streamedLines: string[] = [];
    const ndjsonSink = new NdjsonAuditSink({
      maxBufferedLines: 100,
      onLine: (line) => {
        streamedLines.push(line);
      }
    });

    const hmacSecret = "siem-ndjson-hmac-secret-key-2026";
    const signer = new HmacAuditSigner({
      secretKey: hmacSecret,
      keyId: "siem-k1"
    });

    const logger = new AuditLogger({
      sinks: [
        {
          write: async (entry) => {
            const signed = await signer.signEntry(entry);
            await ndjsonSink.write(signed);
          }
        }
      ]
    });

    for (let i = 0; i < 3; i += 1) {
      await logger.record({
        requestId: `nd-${i}`,
        principalId: "siem-agent",
        method: "tools/call",
        operationKind: "tool",
        target: "db:query",
        decision: "ALLOW",
        reasonCode: "ALLOWED_BY_POLICY",
        matchedRuleId: "r-db",
        detail: "Allowed query",
        latencyMs: 0.14,
        argumentsToLog: { sql: "SELECT 1", token: "secret-tok" }
      });
    }

    assert.equal(streamedLines.length, 3);
    const ndjsonDocument = ndjsonSink.toNdjson();

    const parsed = parseAuditNdjson(ndjsonDocument, { requireHmac: true });
    assert.equal(parsed.ok, true);
    if (parsed.ok) {
      assert.equal(parsed.lineCount, 3);
    }

    const verified = await verifyAuditNdjson(ndjsonDocument, {
      hmacSecretOrKeyRing: { secretKey: hmacSecret, keyId: "siem-k1" }
    });
    assert.equal(verified.valid, true);
    assert.equal(verified.checkedCount, 3);

    // Rejects malformed NDJSON lines and enforces maxLines ceiling
    const brokenSyntax = parseAuditNdjson(`${ndjsonDocument}{bad-json\n`);
    assert.equal(brokenSyntax.ok, false);

    const exceededLines = parseAuditNdjson(ndjsonDocument, { maxLines: 2 });
    assert.equal(exceededLines.ok, false);
  });
});
