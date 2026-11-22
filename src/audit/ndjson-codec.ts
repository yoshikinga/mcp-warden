import type {
  AuditEntry,
  AuditSink,
  ChainVerificationReport
} from "../types/audit.js";
import type { HmacAuditConfig } from "../types/v1-1.js";
import { canonicalizeJson } from "./canonical-json.js";
import { verifyAuditChain } from "./hash-chain.js";
import {
  verifySignedAuditChain,
  type SignedAuditEntry,
  type VerifySignedChainOptions
} from "./hmac-signer.js";

const DEFAULT_MAX_NDJSON_LINES = 100_000;
const DEFAULT_MAX_LINE_BYTES = 131_072; // 128 KiB per line
const UTF8_ENCODER = new TextEncoder();

const VALID_DECISIONS: ReadonlySet<string> = new Set(["ALLOW", "DENY"]);
const VALID_OPERATIONS: ReadonlySet<string> = new Set([
  "tool",
  "resource",
  "prompt",
  "lifecycle",
  "unknown"
]);
const VALID_REASON_CODES: ReadonlySet<string> = new Set([
  "ALLOWED_BY_POLICY",
  "ALLOWED_DISCOVERY",
  "INVALID_ENVELOPE",
  "PAYLOAD_LIMIT_EXCEEDED",
  "EVASION_DETECTED",
  "RATE_LIMIT_EXCEEDED",
  "POLICY_EXPLICIT_DENY",
  "POLICY_NO_MATCH_FAIL_CLOSED",
  "ARGUMENT_CONSTRAINT_FAILED",
  "PATH_TRAVERSAL_BLOCKED",
  "SENSITIVE_FILE_BLOCKED",
  "COMMAND_INJECTION_BLOCKED",
  "SSRF_BLOCKED"
]);

export interface NdjsonParseOptions {
  /** Maximum non-empty NDJSON lines accepted (default: 100000) */
  readonly maxLines?: number;
  /** Maximum UTF-8 byte length per single NDJSON line (default: 131072) */
  readonly maxLineBytes?: number;
  /** Require every record to include `hmacKeyId` and `hmacSignature` (default: false) */
  readonly requireHmac?: boolean;
}

export type NdjsonParseResult =
  | {
      readonly ok: true;
      readonly entries: readonly (AuditEntry | SignedAuditEntry)[];
      readonly lineCount: number;
    }
  | {
      readonly ok: false;
      readonly lineNumber: number;
      readonly reason: string;
    };

export interface VerifyAuditNdjsonOptions extends VerifySignedChainOptions {
  /** When provided, enforces HMAC-SHA256 verification alongside SHA-256 chain checks */
  readonly hmacSecretOrKeyRing?: HmacAuditConfig | Readonly<Record<string, string>>;
  readonly maxLines?: number;
  readonly maxLineBytes?: number;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHex64(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== 64) {
    return false;
  }
  for (let i = 0; i < 64; i += 1) {
    const code = value.charCodeAt(i);
    const isHex =
      (code >= 48 && code <= 57) ||
      (code >= 97 && code <= 102) ||
      (code >= 65 && code <= 70);
    if (!isHex) {
      return false;
    }
  }
  return true;
}

function validateParsedAuditRecord(
  candidate: unknown,
  requireHmac: boolean
): { readonly ok: true; readonly entry: AuditEntry | SignedAuditEntry } | { readonly ok: false; readonly reason: string } {
  if (!isPlainRecord(candidate)) {
    return { ok: false, reason: "NDJSON line is not a JSON object." };
  }

  const seq = candidate["sequence"];
  if (typeof seq !== "number" || !Number.isInteger(seq) || seq < 0) {
    return { ok: false, reason: "Invalid or missing integer 'sequence'." };
  }

  if (typeof candidate["timestamp"] !== "string" || candidate["timestamp"].length === 0) {
    return { ok: false, reason: "Invalid or missing 'timestamp'." };
  }

  const reqId = candidate["requestId"];
  if (
    reqId !== null &&
    typeof reqId !== "string" &&
    (typeof reqId !== "number" || !Number.isFinite(reqId))
  ) {
    return { ok: false, reason: "Invalid 'requestId' field." };
  }

  if (typeof candidate["principalId"] !== "string" || candidate["principalId"].length === 0) {
    return { ok: false, reason: "Invalid or missing 'principalId'." };
  }

  const sessId = candidate["sessionId"];
  if (sessId !== null && typeof sessId !== "string") {
    return { ok: false, reason: "Invalid 'sessionId' field." };
  }

  if (typeof candidate["method"] !== "string" || candidate["method"].length === 0) {
    return { ok: false, reason: "Invalid or missing 'method'." };
  }

  const opKind = candidate["operationKind"];
  if (typeof opKind !== "string" || !VALID_OPERATIONS.has(opKind)) {
    return { ok: false, reason: "Invalid 'operationKind' value." };
  }

  if (typeof candidate["target"] !== "string" || candidate["target"].length === 0) {
    return { ok: false, reason: "Invalid or missing 'target'." };
  }

  const decision = candidate["decision"];
  if (typeof decision !== "string" || !VALID_DECISIONS.has(decision)) {
    return { ok: false, reason: "Invalid 'decision' value." };
  }

  const reasonCode = candidate["reasonCode"];
  if (typeof reasonCode !== "string" || !VALID_REASON_CODES.has(reasonCode)) {
    return { ok: false, reason: "Invalid 'reasonCode' value." };
  }

  const matchedRuleId = candidate["matchedRuleId"];
  if (matchedRuleId !== null && typeof matchedRuleId !== "string") {
    return { ok: false, reason: "Invalid 'matchedRuleId' field." };
  }

  if (typeof candidate["detail"] !== "string") {
    return { ok: false, reason: "Invalid or missing 'detail'." };
  }

  const latencyMs = candidate["latencyMs"];
  if (typeof latencyMs !== "number" || !Number.isFinite(latencyMs) || latencyMs < 0) {
    return { ok: false, reason: "Invalid 'latencyMs' field." };
  }

  if (!isPlainRecord(candidate["redactedArguments"])) {
    return { ok: false, reason: "Invalid 'redactedArguments' object." };
  }

  if (!isHex64(candidate["prevHash"]) || !isHex64(candidate["hash"])) {
    return { ok: false, reason: "Invalid 64-char hex 'prevHash' or 'hash'." };
  }

  const hmacKeyId = candidate["hmacKeyId"];
  const hmacSig = candidate["hmacSignature"];

  if (requireHmac || hmacKeyId !== undefined || hmacSig !== undefined) {
    if (typeof hmacKeyId !== "string" || hmacKeyId.length === 0 || !isHex64(hmacSig)) {
      return {
        ok: false,
        reason: "Incomplete or malformed HMAC-SHA256 signature fields."
      };
    }
  }

  return {
    ok: true,
    entry: candidate as unknown as AuditEntry | SignedAuditEntry
  };
}

/**
 * Serializes a single `AuditEntry` or `SignedAuditEntry` into a canonical NDJSON line (with trailing `\n`).
 */
export function serializeAuditEntryNdjsonLine(
  entry: AuditEntry | SignedAuditEntry
): string {
  return `${canonicalizeJson(entry)}\n`;
}

/**
 * Serializes an ordered list of audit records into a canonical NDJSON document.
 */
export function serializeAuditEntriesToNdjson(
  entries: readonly (AuditEntry | SignedAuditEntry)[]
): string {
  if (entries.length === 0) {
    return "";
  }
  let output = "";
  for (let i = 0; i < entries.length; i += 1) {
    const entry = entries[i];
    if (entry !== undefined) {
      output += serializeAuditEntryNdjsonLine(entry);
    }
  }
  return output;
}

/**
 * Safely parses and schema-validates an NDJSON audit log stream with strict line and byte bounds.
 */
export function parseAuditNdjson(
  ndjsonText: string,
  options: NdjsonParseOptions = {}
): NdjsonParseResult {
  const maxLines = Math.max(1, options.maxLines ?? DEFAULT_MAX_NDJSON_LINES);
  const maxLineBytes = Math.max(256, options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES);
  const requireHmac = options.requireHmac ?? false;

  if (ndjsonText.trim().length === 0) {
    return { ok: true, entries: [], lineCount: 0 };
  }

  const rawLines = ndjsonText.split(/\r?\n/);
  const entries: (AuditEntry | SignedAuditEntry)[] = [];

  for (let i = 0; i < rawLines.length; i += 1) {
    const rawLine = rawLines[i];
    if (rawLine === undefined) {
      continue;
    }
    const trimmed = rawLine.trim();
    if (trimmed.length === 0) {
      continue;
    }

    const lineNumber = i + 1;
    if (entries.length >= maxLines) {
      return {
        ok: false,
        lineNumber,
        reason: `NDJSON stream exceeded maximum allowed lines (${maxLines}).`
      };
    }

    const byteLen = UTF8_ENCODER.encode(trimmed).byteLength;
    if (byteLen > maxLineBytes) {
      return {
        ok: false,
        lineNumber,
        reason: `NDJSON line ${lineNumber} (${byteLen} bytes) exceeds maxLineBytes (${maxLineBytes}).`
      };
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(trimmed) as unknown;
    } catch {
      return {
        ok: false,
        lineNumber,
        reason: `Malformed JSON syntax at NDJSON line ${lineNumber}.`
      };
    }

    const validation = validateParsedAuditRecord(parsedJson, requireHmac);
    if (!validation.ok) {
      return {
        ok: false,
        lineNumber,
        reason: `Schema validation failed at line ${lineNumber}: ${validation.reason}`
      };
    }

    entries.push(validation.entry);
  }

  return {
    ok: true,
    entries,
    lineCount: entries.length
  };
}

/**
 * Parses an NDJSON audit log and verifies its cryptographic SHA-256 (and optional HMAC-SHA256) integrity.
 */
export async function verifyAuditNdjson(
  ndjsonText: string,
  options: VerifyAuditNdjsonOptions = {}
): Promise<ChainVerificationReport> {
  const parsed = parseAuditNdjson(ndjsonText, {
    ...(options.maxLines !== undefined ? { maxLines: options.maxLines } : {}),
    ...(options.maxLineBytes !== undefined
      ? { maxLineBytes: options.maxLineBytes }
      : {}),
    requireHmac: options.hmacSecretOrKeyRing !== undefined
  });

  if (!parsed.ok) {
    return {
      valid: false,
      checkedCount: 0,
      brokenAtSequence: null,
      reason: `NDJSON parse error (line ${parsed.lineNumber}): ${parsed.reason}`
    };
  }

  if (options.hmacSecretOrKeyRing !== undefined) {
    return verifySignedAuditChain(
      parsed.entries,
      options.hmacSecretOrKeyRing,
      options
    );
  }

  return verifyAuditChain(parsed.entries, options);
}

/**
 * SIEM-ready `AuditSink` formatting every sealed record as a canonical NDJSON line,
 * supporting real-time streaming callbacks and bounded in-memory retention.
 */
export class NdjsonAuditSink implements AuditSink {
  private readonly maxBufferedLines: number;
  private readonly onLine:
    | ((line: string, entry: AuditEntry | SignedAuditEntry) => void | Promise<void>)
    | null;
  private readonly lines: string[] = [];

  public constructor(options: {
    readonly maxBufferedLines?: number;
    readonly onLine?: (
      line: string,
      entry: AuditEntry | SignedAuditEntry
    ) => void | Promise<void>;
  } = {}) {
    this.maxBufferedLines = Math.max(0, options.maxBufferedLines ?? 1_000);
    this.onLine = options.onLine ?? null;
  }

  public async write(entry: AuditEntry | SignedAuditEntry): Promise<void> {
    const line = serializeAuditEntryNdjsonLine(entry);

    if (this.maxBufferedLines > 0) {
      if (this.lines.length >= this.maxBufferedLines) {
        this.lines.shift();
      }
      this.lines.push(line);
    }

    if (this.onLine !== null) {
      await this.onLine(line, entry);
    }
  }

  public getLines(): readonly string[] {
    return [...this.lines];
  }

  public toNdjson(): string {
    return this.lines.join("");
  }

  public clear(): void {
    this.lines.length = 0;
  }
}
