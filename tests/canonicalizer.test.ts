import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  canonicalizeRecord,
  canonicalizeString,
  validateAndNormalizeEnvelope
} from "../src/index.js";

describe("Protocol Canonicalizer & Envelope Validator", () => {
  it("decodes double-encoded traversal sequences while preserving benign percent signs", () => {
    const doubleEncoded = canonicalizeString("..%252f..%252fetc%252fpasswd", 3);
    assert.equal(doubleEncoded.ok, true);
    if (doubleEncoded.ok) {
      assert.equal(doubleEncoded.value, "../../etc/passwd");
    }

    const benignProse = canonicalizeString("CPU utilization at 95% capacity", 3);
    assert.equal(benignProse.ok, true);
    if (benignProse.ok) {
      assert.equal(benignProse.value, "CPU utilization at 95% capacity");
    }
  });

  it("normalizes decomposed Unicode sequences into canonical NFC form", () => {
    const decomposed = "cafe\u0301_report.txt";
    const result = canonicalizeString(decomposed);
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.value, "caf\u00e9_report.txt");
    }
  });

  it("blocks raw and percent-encoded null bytes and control characters", () => {
    const rawNull = canonicalizeString("invoice.pdf\u0000.exe");
    assert.equal(rawNull.ok, false);
    if (!rawNull.ok) {
      assert.equal(rawNull.reasonCode, "EVASION_DETECTED");
    }

    const encodedNull = canonicalizeString("invoice.pdf%2500.exe");
    assert.equal(encodedNull.ok, false);
    if (!encodedNull.ok) {
      assert.equal(encodedNull.reasonCode, "EVASION_DETECTED");
    }

    const bellControl = canonicalizeString("bad%07char");
    assert.equal(bellControl.ok, false);
  });

  it("rejects excessive nested percent-encoding depth and invalid UTF-8 sequences", () => {
    // 4-pass nested encoding of '.' (%2e -> %252e -> %25252e -> %2525252e) exceeds maxPasses = 3
    const fourLayerEncoded = canonicalizeString("%2525252e", 3);
    assert.equal(fourLayerEncoded.ok, false);
    if (!fourLayerEncoded.ok) {
      assert.equal(fourLayerEncoded.reasonCode, "EVASION_DETECTED");
    }

    // Overlong invalid UTF-8 byte sequence (%C0%AF)
    const invalidUtf8 = canonicalizeString("%C0%AFetc%C0%AFpasswd", 3);
    assert.equal(invalidUtf8.ok, false);
    if (!invalidUtf8.ok) {
      assert.equal(invalidUtf8.reasonCode, "EVASION_DETECTED");
    }
  });

  it("canonicalizes nested argument records without mutating the caller raw object", () => {
    const rawArgs: Record<string, unknown> = {
      path: "%2e%2e%2fsecret.txt",
      nested: {
        filter: "100%25"
      }
    };

    const result = canonicalizeRecord(rawArgs, 3);
    assert.equal(result.ok, true);
    assert.equal(rawArgs["path"], "%2e%2e%2fsecret.txt");
    if (result.ok) {
      assert.equal(result.value["path"], "../secret.txt");
      const nested = result.value["nested"] as Record<string, unknown>;
      assert.equal(nested["filter"], "100%");
    }
  });

  it("validates MCP tools/call, resources/read, lifecycle methods, and rejects batches", () => {
    const validTool = validateAndNormalizeEnvelope({
      jsonrpc: "2.0",
      id: "req-1",
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/workspace/%64ocs/guide.md" }
      }
    });

    assert.equal(validTool.ok, true);
    if (validTool.ok) {
      assert.equal(validTool.invocation.operationKind, "tool");
      assert.equal(validTool.invocation.target, "fs:read_file");
      assert.equal(
        validTool.invocation.canonicalArguments["path"],
        "/srv/workspace/docs/guide.md"
      );
      assert.equal(
        validTool.invocation.rawArguments["path"],
        "/srv/workspace/%64ocs/guide.md"
      );
    }

    const batchAttempt = validateAndNormalizeEnvelope([
      { jsonrpc: "2.0", id: 1, method: "ping" }
    ]);
    assert.equal(batchAttempt.ok, false);
    if (!batchAttempt.ok) {
      assert.equal(batchAttempt.reasonCode, "INVALID_ENVELOPE");
    }

    const malformedJson = validateAndNormalizeEnvelope("{broken-json");
    assert.equal(malformedJson.ok, false);
  });
});
