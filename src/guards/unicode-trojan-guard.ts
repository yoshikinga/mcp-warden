import type { NormalizedMcpInvocation } from "../types/mcp.js";
import type { UnicodeGuardConfig, UnicodeGuardResult } from "../types/v1-1.js";

interface TraversalFrame {
  readonly value: unknown;
  readonly path: string;
}

function formatCodePointHex(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Detects Trojan Source bidirectional control characters (CVE-2021-42574).
 */
function isBidiControlCodePoint(cp: number): boolean {
  // U+061C (ALM), U+200E (LRM), U+200F (RLM)
  if (cp === 0x061c || cp === 0x200e || cp === 0x200f) {
    return true;
  }
  // U+202A..U+202E (LRE, RLE, PDF, LRO, RLO)
  if (cp >= 0x202a && cp <= 0x202e) {
    return true;
  }
  // U+2066..U+2069 (LRI, RLI, FSI, PDI)
  return cp >= 0x2066 && cp <= 0x2069;
}

/**
 * Detects invisible zero-width format characters used to split tokens or evade dotfile filters.
 */
function isZeroWidthCodePoint(cp: number): boolean {
  // U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+2060 (Word Joiner), U+FEFF (BOM)
  return (
    cp === 0x200b ||
    cp === 0x200c ||
    cp === 0x200d ||
    cp === 0x2060 ||
    cp === 0xfeff
  );
}

/**
 * Detects Unicode Plane 14 Tag characters (U+E0000..U+E007F) used in invisible LLM ASCII smuggling.
 */
function isPlane14TagCodePoint(cp: number): boolean {
  return cp >= 0xe0000 && cp <= 0xe007f;
}

/**
 * Linear-time O(n) guard blocking Trojan Source bidirectional overrides, zero-width token
 * splitters, and Unicode Plane 14 invisible ASCII tag smuggling across MCP payloads.
 */
export class UnicodeTrojanGuard {
  private readonly enabled: boolean;
  private readonly blockBidiControls: boolean;
  private readonly blockZeroWidthChars: boolean;
  private readonly blockTagCharacters: boolean;

  public constructor(config: UnicodeGuardConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.blockBidiControls = config.blockBidiControls ?? true;
    this.blockZeroWidthChars = config.blockZeroWidthChars ?? true;
    this.blockTagCharacters = config.blockTagCharacters ?? true;
  }

  /**
   * Scans target identifiers and canonicalized arguments of an MCP invocation.
   */
  public check(invocation: NormalizedMcpInvocation): UnicodeGuardResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    const targetScan = this.scanString(invocation.target, "target");
    if (!targetScan.allowed) {
      return targetScan;
    }

    return this.scanValue(invocation.canonicalArguments, "arguments");
  }

  /**
   * Scans an arbitrary JSON value or string tree iteratively without recursion limits.
   */
  public scanValue(rootValue: unknown, rootPath: string = "root"): UnicodeGuardResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    const visited = new Set<object>();
    const stack: TraversalFrame[] = [{ value: rootValue, path: rootPath }];

    while (stack.length > 0) {
      const frame = stack.pop();
      if (frame === undefined) {
        break;
      }

      const { value, path } = frame;

      if (typeof value === "string") {
        const strResult = this.scanString(value, path);
        if (!strResult.allowed) {
          return strResult;
        }
        continue;
      }

      if (typeof value !== "object" || value === null) {
        continue;
      }

      if (visited.has(value)) {
        continue;
      }
      visited.add(value);

      if (Array.isArray(value)) {
        for (let i = value.length - 1; i >= 0; i -= 1) {
          stack.push({ value: value[i], path: `${path}[${i}]` });
        }
        continue;
      }

      const record = value as Record<string, unknown>;
      const keys = Object.keys(record);
      for (let i = keys.length - 1; i >= 0; i -= 1) {
        const key = keys[i];
        if (key === undefined) {
          continue;
        }
        const keyPath = `${path}.${key}`;
        const keyCheck = this.scanString(key, `${keyPath}(key)`);
        if (!keyCheck.allowed) {
          return keyCheck;
        }
        stack.push({ value: record[key], path: keyPath });
      }
    }

    return { allowed: true };
  }

  /**
   * Inspects a single UTF-16 string by full Unicode code points (handling surrogate pairs).
   */
  public scanString(text: string, fieldPath: string): UnicodeGuardResult {
    if (!this.enabled || text.length === 0) {
      return { allowed: true };
    }

    for (let index = 0; index < text.length; ) {
      const cp = text.codePointAt(index);
      if (cp === undefined) {
        break;
      }

      if (this.blockBidiControls && isBidiControlCodePoint(cp)) {
        const hex = formatCodePointHex(cp);
        return {
          allowed: false,
          reasonCode: "UNICODE_TROJAN_DETECTED",
          fieldPath,
          codePointHex: hex,
          detail: `Trojan Source bidirectional control character (${hex}) detected in '${fieldPath}'.`
        };
      }

      if (this.blockZeroWidthChars && isZeroWidthCodePoint(cp)) {
        const hex = formatCodePointHex(cp);
        return {
          allowed: false,
          reasonCode: "UNICODE_TROJAN_DETECTED",
          fieldPath,
          codePointHex: hex,
          detail: `Invisible zero-width evasion character (${hex}) detected in '${fieldPath}'.`
        };
      }

      if (this.blockTagCharacters && isPlane14TagCodePoint(cp)) {
        const hex = formatCodePointHex(cp);
        return {
          allowed: false,
          reasonCode: "UNICODE_TROJAN_DETECTED",
          fieldPath,
          codePointHex: hex,
          detail: `Unicode Plane 14 invisible tag smuggling character (${hex}) detected in '${fieldPath}'.`
        };
      }

      index += cp > 0xffff ? 2 : 1;
    }

    return { allowed: true };
  }
}
