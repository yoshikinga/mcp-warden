import type {
  AuditEntry,
  ChainVerificationReport,
  UnsignedAuditEntry
} from "../types/audit.js";
import type { HmacAuditConfig } from "../types/v1-1.js";
import { canonicalizeJson } from "./canonical-json.js";
import { verifyAuditChain, type VerifyChainOptions } from "./hash-chain.js";

/**
 * Default key identifier assigned when `HmacAuditConfig.keyId` is omitted.
 */
export const DEFAULT_HMAC_KEY_ID = "default";

const UTF8_ENCODER = new TextEncoder();

/**
 * Tamper-proof audit record extending SHA-256 hash chaining with a secret-keyed
 * HMAC-SHA256 cryptographic authentication tag.
 */
export interface SignedAuditEntry extends AuditEntry {
  readonly hmacKeyId: string;
  readonly hmacSignature: string;
}

/**
 * Verification options for `verifySignedAuditChain`, including tail-truncation guards.
 */
export interface VerifySignedChainOptions extends VerifyChainOptions {
  /** Optional expected entry count to detect tail-truncation attacks */
  readonly expectedCount?: number;
  /** Optional expected final entry SHA-256 hash to anchor chain head */
  readonly expectedLastHash?: string;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = bytes[i] ?? 0;
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

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
 * Type guard checking whether an `AuditEntry` carries HMAC-SHA256 signature fields.
 */
export function isSignedAuditEntry(
  entry: AuditEntry
): entry is SignedAuditEntry {
  const candidate = entry as unknown as Readonly<Record<string, unknown>>;
  return (
    typeof candidate["hmacKeyId"] === "string" &&
    candidate["hmacKeyId"].length > 0 &&
    typeof candidate["hmacSignature"] === "string" &&
    candidate["hmacSignature"].length === 64
  );
}

/**
 * Builds the canonical deterministic payload bound under HMAC-SHA256.
 */
export function buildAuditHmacPayload(
  entry: AuditEntry,
  keyId: string
): string {
  const unsignedPortion: UnsignedAuditEntry = {
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

  return `${keyId}|${entry.sequence}|${entry.prevHash}|${entry.hash}|${canonicalizeJson(unsignedPortion)}`;
}

async function importHmacKey(secretKey: string): Promise<CryptoKey> {
  if (secretKey.trim().length === 0) {
    throw new Error("HMAC audit secretKey must be a non-empty string.");
  }

  const subtle = globalThis.crypto?.subtle;
  if (subtle === undefined) {
    throw new Error(
      "Web Crypto API (globalThis.crypto.subtle) is unavailable in this runtime."
    );
  }

  return subtle.importKey(
    "raw",
    UTF8_ENCODER.encode(secretKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/**
 * Computes a lowercase hexadecimal HMAC-SHA256 digest using standard Web Crypto.
 */
export async function computeHmacSha256Hex(
  secretKey: string,
  payload: string
): Promise<string> {
  const cryptoKey = await importHmacKey(secretKey);
  const subtle = globalThis.crypto.subtle;
  const macBuffer = await subtle.sign(
    "HMAC",
    cryptoKey,
    UTF8_ENCODER.encode(payload)
  );
  return bytesToHex(new Uint8Array(macBuffer));
}

/**
 * Stateful HMAC-SHA256 signer that caches the imported Web Crypto `CryptoKey`
 * so per-request signing adds sub-millisecond overhead.
 */
export class HmacAuditSigner {
  private readonly secretKey: string;
  private readonly keyId: string;
  private cachedKeyPromise: Promise<CryptoKey> | null = null;

  public constructor(config: HmacAuditConfig) {
    if (config.secretKey.trim().length === 0) {
      throw new Error("HmacAuditSigner requires a non-empty secretKey.");
    }
    this.secretKey = config.secretKey;
    this.keyId =
      config.keyId !== undefined && config.keyId.trim().length > 0
        ? config.keyId.trim()
        : DEFAULT_HMAC_KEY_ID;
  }

  public getKeyId(): string {
    return this.keyId;
  }

  public async signPayload(payload: string): Promise<string> {
    if (this.cachedKeyPromise === null) {
      this.cachedKeyPromise = importHmacKey(this.secretKey);
    }
    const cryptoKey = await this.cachedKeyPromise;
    const macBuffer = await globalThis.crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      UTF8_ENCODER.encode(payload)
    );
    return bytesToHex(new Uint8Array(macBuffer));
  }

  public async signEntry(entry: AuditEntry): Promise<SignedAuditEntry> {
    const payload = buildAuditHmacPayload(entry, this.keyId);
    const hmacSignature = await this.signPayload(payload);
    return {
      ...entry,
      hmacKeyId: this.keyId,
      hmacSignature
    };
  }

  public async verifyEntry(entry: SignedAuditEntry): Promise<boolean> {
    if (entry.hmacKeyId !== this.keyId) {
      return false;
    }
    const expected = await this.signPayload(
      buildAuditHmacPayload(entry, entry.hmacKeyId)
    );
    return constantTimeHexEqual(entry.hmacSignature, expected);
  }
}

/**
 * Convenience helper to sign a single `AuditEntry` with an `HmacAuditConfig`.
 */
export async function signAuditEntry(
  entry: AuditEntry,
  config: HmacAuditConfig
): Promise<SignedAuditEntry> {
  const signer = new HmacAuditSigner(config);
  return signer.signEntry(entry);
}

function resolveSecretFromSource(
  source: HmacAuditConfig | Readonly<Record<string, string>>,
  requestedKeyId: string
): string | null {
  const record = source as Readonly<Record<string, unknown>>;
  if (typeof record["secretKey"] === "string") {
    const configuredKeyId =
      typeof record["keyId"] === "string" && record["keyId"].trim().length > 0
        ? record["keyId"].trim()
        : DEFAULT_HMAC_KEY_ID;
    return configuredKeyId === requestedKeyId ? record["secretKey"] : null;
  }

  const ringSecret = record[requestedKeyId];
  return typeof ringSecret === "string" && ringSecret.trim().length > 0
    ? ringSecret
    : null;
}

/**
 * Verifies both the unkeyed SHA-256 chain links AND every entry's secret-keyed HMAC-SHA256
 * authentication tag. Accepts either a single `HmacAuditConfig` or a `{ [keyId]: secretKey }`
 * key-ring dictionary for enterprise key rotation.
 */
export async function verifySignedAuditChain(
  entries: readonly AuditEntry[],
  secretOrKeyRing: HmacAuditConfig | Readonly<Record<string, string>>,
  options: VerifySignedChainOptions = {}
): Promise<ChainVerificationReport> {
  const baseReport = await verifyAuditChain(entries, options);
  if (!baseReport.valid) {
    return baseReport;
  }

  if (
    options.expectedCount !== undefined &&
    entries.length !== options.expectedCount
  ) {
    const lastSeq =
      entries.length > 0
        ? (entries[entries.length - 1]?.sequence ?? null)
        : null;
    return {
      valid: false,
      checkedCount: entries.length,
      brokenAtSequence: lastSeq,
      reason: `Audit chain length mismatch: expected ${options.expectedCount} entries, found ${entries.length}.`
    };
  }

  if (options.expectedLastHash !== undefined && entries.length > 0) {
    const lastEntry = entries[entries.length - 1];
    if (
      lastEntry !== undefined &&
      !constantTimeHexEqual(lastEntry.hash, options.expectedLastHash)
    ) {
      return {
        valid: false,
        checkedCount: entries.length - 1,
        brokenAtSequence: lastEntry.sequence,
        reason: `Final audit entry hash at sequence ${lastEntry.sequence} does not match expected head anchor.`
      };
    }
  }

  const signerCache = new Map<string, HmacAuditSigner>();

  for (let i = 0; i < entries.length; i += 1) {
    const current = entries[i];
    if (current === undefined) {
      continue;
    }

    if (!isSignedAuditEntry(current)) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequence: current.sequence,
        reason: `Audit entry at sequence ${current.sequence} is missing required HMAC-SHA256 signature fields.`
      };
    }

    let signer = signerCache.get(current.hmacKeyId);
    if (signer === undefined) {
      const secretKey = resolveSecretFromSource(
        secretOrKeyRing,
        current.hmacKeyId
      );
      if (secretKey === null) {
        return {
          valid: false,
          checkedCount: i,
          brokenAtSequence: current.sequence,
          reason: `Unknown or unauthorized HMAC keyId '${current.hmacKeyId}' at sequence ${current.sequence}.`
        };
      }
      signer = new HmacAuditSigner({
        secretKey,
        keyId: current.hmacKeyId
      });
      signerCache.set(current.hmacKeyId, signer);
    }

    const signatureValid = await signer.verifyEntry(current);
    if (!signatureValid) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtSequence: current.sequence,
        reason: `HMAC-SHA256 signature verification failed at sequence ${current.sequence}.`
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
