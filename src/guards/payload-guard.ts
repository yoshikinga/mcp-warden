import type { AuditReasonCode } from "../types/audit.js";
import type { PayloadGuardConfig } from "../types/policy.js";

/**
 * Shared result contract returned by inline threat guards.
 */
export type GuardCheckResult =
  | {
      readonly allowed: true;
    }
  | {
      readonly allowed: false;
      readonly reasonCode: AuditReasonCode;
      readonly detail: string;
    };

const DEFAULT_MAX_BYTES = 65_536; // 64 KiB
const DEFAULT_MAX_DEPTH = 12;
const DEFAULT_MAX_KEYS = 250;
const DEFAULT_MAX_STRING_LENGTH = 16_384;

const UTF8_ENCODER = new TextEncoder();

interface StackFrame {
  readonly value: unknown;
  readonly depth: number;
}

/**
 * Protects the MCP gateway from Denial-of-Service (DoS) payloads by enforcing hard ceilings
 * on UTF-8 byte size, JSON nesting depth, total object keys, and single string length.
 */
export class PayloadGuard {
  private readonly enabled: boolean;
  private readonly maxBytes: number;
  private readonly maxDepth: number;
  private readonly maxKeys: number;
  private readonly maxStringLength: number;
  private readonly rejectBatchRequests: boolean;

  public constructor(config: PayloadGuardConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.maxBytes = config.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxDepth = config.maxDepth ?? DEFAULT_MAX_DEPTH;
    this.maxKeys = config.maxKeys ?? DEFAULT_MAX_KEYS;
    this.maxStringLength = config.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH;
    this.rejectBatchRequests = config.rejectBatchRequests ?? true;
  }

  /**
   * Inspects raw string or pre-parsed object payloads using an explicit heap stack
   * so adversarial deep trees can never trigger call-stack overflow.
   */
  public check(rawInput: unknown): GuardCheckResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    let rootValue: unknown = rawInput;

    if (typeof rawInput === "string") {
      const byteLength = UTF8_ENCODER.encode(rawInput).byteLength;
      if (byteLength > this.maxBytes) {
        return {
          allowed: false,
          reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
          detail: `Raw request size (${byteLength} bytes) exceeds maximum budget (${this.maxBytes} bytes).`
        };
      }

      try {
        rootValue = JSON.parse(rawInput) as unknown;
      } catch {
        // Malformed JSON syntax is handled downstream by EnvelopeValidator as INVALID_ENVELOPE.
        return { allowed: true };
      }
    } else {
      let serialized: string;
      try {
        serialized = JSON.stringify(rawInput) ?? "";
      } catch {
        return {
          allowed: false,
          reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
          detail: "Payload contains circular references or non-serializable values."
        };
      }

      const byteLength = UTF8_ENCODER.encode(serialized).byteLength;
      if (byteLength > this.maxBytes) {
        return {
          allowed: false,
          reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
          detail: `Serialized request size (${byteLength} bytes) exceeds maximum budget (${this.maxBytes} bytes).`
        };
      }
    }

    if (Array.isArray(rootValue) && this.rejectBatchRequests) {
      return {
        allowed: false,
        reasonCode: "INVALID_ENVELOPE",
        detail: "JSON-RPC batch array requests are disallowed by PayloadGuard."
      };
    }

    let totalKeys = 0;
    const visitedObjects = new Set<object>();
    const stack: StackFrame[] = [{ value: rootValue, depth: 0 }];

    while (stack.length > 0) {
      const current = stack.pop();
      if (current === undefined) {
        break;
      }

      const { value, depth } = current;

      if (depth > this.maxDepth) {
        return {
          allowed: false,
          reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
          detail: `JSON nesting depth (${depth}) exceeds maximum allowed depth (${this.maxDepth}).`
        };
      }

      if (typeof value === "string") {
        if (value.length > this.maxStringLength) {
          return {
            allowed: false,
            reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
            detail: `String value length (${value.length}) exceeds maximum allowed length (${this.maxStringLength}).`
          };
        }
        continue;
      }

      if (typeof value !== "object" || value === null) {
        continue;
      }

      if (visitedObjects.has(value)) {
        return {
          allowed: false,
          reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
          detail: "Circular object reference detected inside request payload."
        };
      }
      visitedObjects.add(value);

      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i += 1) {
          stack.push({ value: value[i], depth: depth + 1 });
        }
        continue;
      }

      const keys = Object.keys(value);
      totalKeys += keys.length;
      if (totalKeys > this.maxKeys) {
        return {
          allowed: false,
          reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
          detail: `Total object key count (${totalKeys}) exceeds maximum allowed keys (${this.maxKeys}).`
        };
      }

      const record = value as Record<string, unknown>;
      for (let i = 0; i < keys.length; i += 1) {
        const key = keys[i];
        if (key === undefined) {
          continue;
        }
        if (key.length > this.maxStringLength) {
          return {
            allowed: false,
            reasonCode: "PAYLOAD_LIMIT_EXCEEDED",
            detail: `Object key length (${key.length}) exceeds maximum allowed length (${this.maxStringLength}).`
          };
        }
        stack.push({ value: record[key], depth: depth + 1 });
      }
    }

    return { allowed: true };
  }
}
