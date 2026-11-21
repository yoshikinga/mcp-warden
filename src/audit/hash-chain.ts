import type {
  AuditEntry,
  ChainVerificationReport,
  UnsignedAuditEntry
} from "../types/audit.js";
import { canonicalizeJson } from "./canonical-json.js";

/**
 * Standard 64-character zero hex string anchoring sequence 0 of an audit chain.
 */
export const GENESIS_PREV_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

const UTF8_ENCODER = new TextEncoder();

export interface VerifyChainOptions {
  /**
   * When true, allows verifying a truncated/rotated subchain window whose first entry
   * has `sequence > 0`, while still verifying contiguous links and SHA-256 digests.
   */
  readonly allowSubchain?: boolean;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i] ?? 0;
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Constant-time string comparison to avoid timing side-channels during digest verification.
 */
function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Computes lowercase hexadecimal SHA-256 digest using standard Web Crypto (`crypto.subtle`).
 */
export async function computeSha256Hex(payload: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new Error(
      "Web Crypto API (globalThis.crypto.subtle) is unavailable in this runtime."
    );
  }

  const encoded = UTF8_ENCODER.encode(payload);
  const digestBuffer = await subtle.digest("SHA-256", encoded);
  return bytesToHex(new Uint8Array(digestBuffer));
}

/**
 * Extracts strictly the unsigned fields of an audit record and computes
 * `SHA-256(prevHash + "|" + canonicalJson(unsignedRecord))`.
 */
export async function computeAuditEntryHash(
  entry: UnsignedAuditEntry
): Promise<string> {
  const cleanUnsigned: UnsignedAuditEntry = {
    sequence: entry.sequence,
    timestamp: entry.timestamp,
    requestId: entry.requestId,
    principalId: entry.principalId,
    sessionId: entry.sessionId,
    method: entry.method,
    operationKind: entry.operationKind,
    target: entry.target,
    decision: entry.decision,
    reasonCode: entry.reasonCode,
    matchedRuleId: entry.matchedRuleId,
    detail: entry.detail,
    latencyMs: entry.latencyMs,
    redactedArguments: entry.redactedArguments,
    prevHash: entry.prevHash
  };

  const canonicalPayload = `${cleanUnsigned.prevHash}|${canonicalizeJson(cleanUnsigned)}`;
  return computeSha256Hex(canonicalPayload);
}

/**
 * Seals an unsigned audit entry with its cryptographic SHA-256 chain digest.
 */
export async function sealAuditEntry(
  unsignedEntry: UnsignedAuditEntry
): Promise<AuditEntry> {
  const hash = await computeAuditEntryHash(unsignedEntry);
  return {
    ...unsignedEntry,
    hash
  };
}

/**
 * Verifies cryptographic integrity, contiguous sequence numbering, and `prevHash` links
 * across an ordered list of `AuditEntry` records.
 */
export async function verifyAuditChain(
  entries: readonly AuditEntry[],
  options: VerifyChainOptions = {}
): Promise<ChainVerificationReport> {
  if (entries.length === 0) {
    return {
      valid: true,
      checkedCount: 0,
      brokenAtSequence: null,
      reason: null
    };
  }

  const allowSubchain = options.allowSubchain ?? false;
  const firstEntry = entries[0];
  if (firstEntry === undefined) {
    return {
      valid: true,
      checkedCount: 0,
      brokenAtSequence: null,
      reason: null
    };
  }

  if (!allowSubchain) {
    if (firstEntry.sequence !== 0) {
      return {
        valid: false,
        checkedCount: 0,
        brokenAtSequence: firstEntry.sequence,
        reason: `Genesis audit entry must start at sequence 0, found ${firstEntry.sequence}.`
      };
    }
    if (!constantTimeHexEqual(firstEntry.prevHash, GENESIS_PREV_HASH)) {
      return {
        valid: false,
        checkedCount: 0,
        brokenAtSequence: firstEntry.sequence,
        reason: "Genesis audit entry prevHash does not match GENESIS_PREV_HASH."
      };
    }
  }

  for (let i = 0; i < entries.length; i += 1) {
    const current = entries[i];
    if (current === undefined) {
      continue;
    }

    if (i > 0) {
      const previous = entries[i - 1];
      if (previous !== undefined) {
        const expectedSequence = previous.sequence + 1;
        if (current.sequence !== expectedSequence) {
          return {
            valid: false,
            checkedCount: i,
            brokenAtSequence: current.sequence,
            reason: `Sequence gap or reordering detected: expected ${expectedSequence}, found ${current.sequence}.`
          };
        }

        if (!constantTimeHexEqual(current.prevHash, previous.hash)) {
          return {
            valid: false,
            checkedCount: i,
            brokenAtSequence: current.sequence,
            reason: `Broken hash link at sequence ${current.sequence}: prevHash does not match preceding entry hash.`
          };
        }
      }
    }

    const recomputedHash = await computeAuditEntryHash(current);
    if (!constantTimeHexEqual(current.hash, recomputedHash)) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequence: current.sequence,
        reason: `SHA-256 digest mismatch at sequence ${current.sequence}: entry content was tampered with.`
      };
    }
  }

  return {
    valid: true,
    checkedCount: entries.length,
    brokenAtSequence: null,
    reason: null
  };
}
