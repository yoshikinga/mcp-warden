import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AuditLogger,
  GENESIS_PREV_HASH,
  REDACTED_MASK,
  RingBufferAuditSink,
  canonicalizeJson,
  verifyAuditChain,
  type AuditEntry
} from "../src/index.js";

describe("Cryptographic SHA-256 Audit Chain & Secret Scrubbing", () => {
  it("produces identical canonical JSON regardless of object key insertion order", () => {
    const first = { z: 1, a: { d: true, c: [3, 2, 1] } };
    const second = { a: { c: [3, 2, 1], d: true }, z: 1 };
    assert.equal(canonicalizeJson(first), canonicalizeJson(second));
  });

  it("maintains unbroken SHA-256 links under concurrent writes and scrubs secrets", async () => {
    const ringSink = new RingBufferAuditSink(50);
    const logger = new AuditLogger({
      sinks: [ringSink],
      sensitiveKeys: ["customerSsn"]
    });

    await Promise.all(
      Array.from({ length: 8 }, (_, idx) =>
        logger.record({
          requestId: idx + 1,
          principalId: `agent-${idx}`,
          sessionId: "sess-concurrent",
          method: "tools/call",
          operationKind: "tool",
          target: "crm:lookup",
          decision: idx % 2 === 0 ? "ALLOW" : "DENY",
          reasonCode:
            idx % 2 === 0 ? "ALLOWED_BY_POLICY" : "POLICY_EXPLICIT_DENY",
          matchedRuleId: "rule-crm",
          detail: `Invocation #${idx}`,
          latencyMs: 0.24,
          argumentsToLog: {
            query: "acct_123",
            apiKey: "sk-live-super-secret",
            customerSsn: "123-45-6789",
            nested: {
              Authorization: "Bearer eyJhbGciOi..."
            }
          }
        })
      )
    );

    const entries = ringSink.getEntries();
    assert.equal(entries.length, 8);
    assert.equal(entries[0]?.prevHash, GENESIS_PREV_HASH);

    const firstRedacted = entries[0]?.redactedArguments ?? {};
    assert.equal(firstRedacted["apiKey"], REDACTED_MASK);
    assert.equal(firstRedacted["customerSsn"], REDACTED_MASK);
    const nestedRedacted = firstRedacted["nested"] as Record<string, unknown>;
    assert.equal(nestedRedacted["Authorization"], REDACTED_MASK);

    const report = await verifyAuditChain(entries);
    assert.equal(report.valid, true);
    assert.equal(report.checkedCount, 8);
    assert.equal(report.brokenAtSequence, null);
  });

  it("detects single-field tampering and deleted records accurately", async () => {
    const ringSink = new RingBufferAuditSink(10);
    const logger = new AuditLogger({ sinks: [ringSink] });

    for (let i = 0; i < 4; i += 1) {
      await logger.record({
        requestId: i,
        principalId: "sec-bot",
        method: "tools/call",
        operationKind: "tool",
        target: "fs:read",
        decision: "DENY",
        reasonCode: "SENSITIVE_FILE_BLOCKED",
        matchedRuleId: null,
        detail: "Blocked .env read",
        latencyMs: 0.18,
        argumentsToLog: { path: ".env" }
      });
    }

    const original = ringSink.getEntries();
    const targetEntry = original[2];
    assert.ok(targetEntry !== undefined);

    // Mutate decision from DENY to ALLOW at sequence 2 without recomputing chain
    const mutatedChain: AuditEntry[] = original.map((entry, idx) =>
      idx === 2 ? { ...entry, decision: "ALLOW" } : entry
    );

    const tamperReport = await verifyAuditChain(mutatedChain);
    assert.equal(tamperReport.valid, false);
    assert.equal(tamperReport.brokenAtSequence, 2);

    // Delete sequence 1 to simulate log deletion attack
    const deletedChain = original.filter((entry) => entry.sequence !== 1);
    const deletionReport = await verifyAuditChain(deletedChain);
    assert.equal(deletionReport.valid, false);
    assert.equal(deletionReport.brokenAtSequence, 2);
  });

  it("verifies rotated RingBuffer subchains when allowSubchain is enabled", async () => {
    const smallSink = new RingBufferAuditSink(3);
    const logger = new AuditLogger({ sinks: [smallSink] });

    for (let i = 0; i < 5; i += 1) {
      await logger.record({
        requestId: i,
        principalId: "worker",
        method: "ping",
        operationKind: "lifecycle",
        target: "ping",
        decision: "ALLOW",
        reasonCode: "ALLOWED_DISCOVERY",
        matchedRuleId: null,
        detail: "ok",
        latencyMs: 0.05,
        argumentsToLog: {}
      });
    }

    assert.equal(smallSink.size(), 3);
    assert.equal(smallSink.hasEvictedEntries(), true);

    const subchainReport = await verifyAuditChain(smallSink.getEntries(), {
      allowSubchain: true
    });
    assert.equal(subchainReport.valid, true);
    assert.equal(subchainReport.checkedCount, 3);
  });
});
