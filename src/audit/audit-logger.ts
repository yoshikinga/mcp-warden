import type {
  AuditDecisionOutcome,
  AuditEntry,
  AuditReasonCode,
  AuditSink,
  UnsignedAuditEntry
} from "../types/audit.js";
import type { JsonRpcId } from "../types/jsonrpc.js";
import type { McpOperationKind } from "../types/mcp.js";
import { GENESIS_PREV_HASH, sealAuditEntry } from "./hash-chain.js";

export const REDACTED_MASK = "[REDACTED]";

const BUILTIN_SENSITIVE_KEY_TOKENS: readonly string[] = [
  "password",
  "passwd",
  "passphrase",
  "secret",
  "token",
  "apikey",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "clientsecret",
  "privatekey",
  "authorization",
  "cookie",
  "setcookie",
  "sessionkey",
  "credential",
  "credentials",
  "bearer",
  "signingkey"
];

function normalizeKeyIdentifier(key: string): string {
  return key.toLowerCase().replaceAll("_", "").replaceAll("-", "");
}

function isSensitiveKeyName(
  rawKey: string,
  customNormalizedKeys: ReadonlySet<string>
): boolean {
  const normalized = normalizeKeyIdentifier(rawKey);
  if (customNormalizedKeys.has(normalized)) {
    return true;
  }
  for (let i = 0; i < BUILTIN_SENSITIVE_KEY_TOKENS.length; i += 1) {
    const token = BUILTIN_SENSITIVE_KEY_TOKENS[i];
    if (token !== undefined && normalized.includes(token)) {
      return true;
    }
  }
  return false;
}

function redactNode(
  value: unknown,
  customNormalizedKeys: ReadonlySet<string>
): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactNode(item, customNormalizedKeys));
  }

  if (typeof value === "object" && value !== null) {
    const source = value as Record<string, unknown>;
    const scrubbed: Record<string, unknown> = {};
    for (const [key, propVal] of Object.entries(source)) {
      if (isSensitiveKeyName(key, customNormalizedKeys)) {
        scrubbed[key] = REDACTED_MASK;
      } else {
        scrubbed[key] = redactNode(propVal, customNormalizedKeys);
      }
    }
    return scrubbed;
  }

  return value;
}

/**
 * Recursively masks sensitive credential fields in an argument dictionary
 * before writing records to audit storage.
 */
export function redactSensitiveArguments(
  args: Readonly<Record<string, unknown>>,
  additionalSensitiveKeys: readonly string[] = []
): Record<string, unknown> {
  const customSet = new Set<string>(
    additionalSensitiveKeys.map((key) => normalizeKeyIdentifier(key))
  );
  return redactNode(args, customSet) as Record<string, unknown>;
}

/**
 * Bounded-memory in-process audit sink retaining up to `maxEntries` most recent records.
 */
export class RingBufferAuditSink implements AuditSink {
  private readonly maxEntries: number;
  private readonly buffer: AuditEntry[] = [];
  private evictedAny = false;

  public constructor(maxEntries: number = 1_000) {
    this.maxEntries = Math.max(1, maxEntries);
  }

  public write(entry: AuditEntry): void {
    if (this.buffer.length >= this.maxEntries) {
      this.buffer.shift();
      this.evictedAny = true;
    }
    this.buffer.push(entry);
  }

  public getEntries(): readonly AuditEntry[] {
    return [...this.buffer];
  }

  public hasEvictedEntries(): boolean {
    return this.evictedAny;
  }

  public size(): number {
    return this.buffer.length;
  }

  public clear(): void {
    this.buffer.length = 0;
    this.evictedAny = false;
  }
}

export interface RecordAuditParams {
  readonly requestId: JsonRpcId;
  readonly principalId: string;
  readonly sessionId?: string;
  readonly method: string;
  readonly operationKind: McpOperationKind;
  readonly target: string;
  readonly decision: AuditDecisionOutcome;
  readonly reasonCode: AuditReasonCode;
  readonly matchedRuleId: string | null;
  readonly detail: string;
  readonly latencyMs: number;
  readonly argumentsToLog: Readonly<Record<string, unknown>>;
}

/**
 * Concurrency-safe cryptographic audit logger that serializes hash-chain sealing
 * through an internal async queue so concurrent calls never fork `prevHash` links.
 */
export class AuditLogger {
  private readonly sinks: readonly AuditSink[];
  private readonly sensitiveKeys: readonly string[];
  private readonly nowFn: () => number;
  private sequence = 0;
  private lastHash: string = GENESIS_PREV_HASH;
  private writeQueue: Promise<void> = Promise.resolve();

  public constructor(options: {
    readonly sinks?: readonly AuditSink[];
    readonly sensitiveKeys?: readonly string[];
    readonly nowFn?: () => number;
  } = {}) {
    this.sinks = options.sinks ?? [];
    this.sensitiveKeys = options.sensitiveKeys ?? [];
    this.nowFn = options.nowFn ?? (() => Date.now());
  }

  public record(params: RecordAuditParams): Promise<AuditEntry> {
    const task = this.writeQueue.then(async (): Promise<AuditEntry> => {
      const redactedArguments = redactSensitiveArguments(
        params.argumentsToLog,
        this.sensitiveKeys
      );

      const unsignedEntry: UnsignedAuditEntry = {
        sequence: this.sequence,
        timestamp: new Date(this.nowFn()).toISOString(),
        requestId: params.requestId,
        principalId: params.principalId,
        sessionId: params.sessionId ?? null,
        method: params.method,
        operationKind: params.operationKind,
        target: params.target,
        decision: params.decision,
        reasonCode: params.reasonCode,
        matchedRuleId: params.matchedRuleId,
        detail: params.detail,
        latencyMs: Math.round(params.latencyMs * 1_000) / 1_000,
        redactedArguments,
        prevHash: this.lastHash
      };

      const sealed = await sealAuditEntry(unsignedEntry);
      this.sequence += 1;
      this.lastHash = sealed.hash;

      for (let i = 0; i < this.sinks.length; i += 1) {
        const sink = this.sinks[i];
        if (sink !== undefined) {
          await sink.write(sealed);
        }
      }

      return sealed;
    });

    // Keep internal mutex alive even if an external sink rejects.
    this.writeQueue = task.then(
      () => undefined,
      () => undefined
    );

    return task;
  }

  public getSequence(): number {
    return this.sequence;
  }

  public getLastHash(): string {
    return this.lastHash;
  }
}
