/**
 * Result union returned by canonicalization routines.
 */
export type CanonicalizeResult<T> =
  | {
      readonly ok: true;
      readonly value: T;
    }
  | {
      readonly ok: false;
      readonly reasonCode: "EVASION_DETECTED";
      readonly detail: string;
    };

const DEFAULT_MAX_DECODE_PASSES = 3;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

function hexValue(charCode: number): number {
  // '0'-'9'
  if (charCode >= 48 && charCode <= 57) {
    return charCode - 48;
  }
  // 'A'-'F'
  if (charCode >= 65 && charCode <= 70) {
    return charCode - 55;
  }
  // 'a'-'f'
  if (charCode >= 97 && charCode <= 102) {
    return charCode - 87;
  }
  return -1;
}

/**
 * Checks for null bytes (\u0000) and disallowed ASCII C0/DEL control characters.
 * Allows standard whitespace: Horizontal Tab (0x09), LF (0x0A), and CR (0x0D).
 */
export function findDisallowedControlChar(input: string): string | null {
  for (let i = 0; i < input.length; i += 1) {
    const code = input.charCodeAt(i);
    if (code === 0) {
      return "Embedded null byte (\\u0000) detected.";
    }
    if ((code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127) {
      return `Disallowed ASCII control character (0x${code.toString(16).padStart(2, "0")}) detected.`;
    }
  }
  return null;
}

/**
 * Performs a single pass of RFC 3986 percent-decoding while tolerating literal '%'
 * signs in benign prose (e.g., "100% coverage") and rejecting invalid/overlong UTF-8 sequences.
 */
function decodePercentSinglePass(input: string): CanonicalizeResult<{
  readonly decoded: string;
  readonly changed: boolean;
}> {
  if (!input.includes("%")) {
    return { ok: true, value: { decoded: input, changed: false } };
  }

  let output = "";
  let changed = false;
  let index = 0;

  while (index < input.length) {
    const code = input.charCodeAt(index);
    if (code !== 37 /* '%' */ || index + 2 >= input.length) {
      output += input.charAt(index);
      index += 1;
      continue;
    }

    const firstHi = hexValue(input.charCodeAt(index + 1));
    const firstLo = hexValue(input.charCodeAt(index + 2));
    if (firstHi === -1 || firstLo === -1) {
      output += input.charAt(index);
      index += 1;
      continue;
    }

    const bytes: number[] = [];
    let cursor = index;
    while (cursor + 2 < input.length && input.charCodeAt(cursor) === 37) {
      const hi = hexValue(input.charCodeAt(cursor + 1));
      const lo = hexValue(input.charCodeAt(cursor + 2));
      if (hi === -1 || lo === -1) {
        break;
      }
      bytes.push((hi << 4) | lo);
      cursor += 3;
    }

    try {
      const decodedChunk = UTF8_DECODER.decode(Uint8Array.from(bytes));
      output += decodedChunk;
      changed = true;
      index = cursor;
    } catch {
      return {
        ok: false,
        reasonCode: "EVASION_DETECTED",
        detail: "Invalid or overlong UTF-8 percent-encoded byte sequence detected."
      };
    }
  }

  return { ok: true, value: { decoded: output, changed } };
}

/**
 * Normalizes Windows backslashes to POSIX forward slashes for uniform inspection.
 */
export function normalizePathSlashes(input: string): string {
  return input.replaceAll("\\", "/");
}

/**
 * Iteratively percent-decodes a string up to `maxPasses`, normalizes Unicode to NFC,
 * and rejects null-byte or deep multi-encoding evasion attempts.
 */
export function canonicalizeString(
  input: string,
  maxPasses: number = DEFAULT_MAX_DECODE_PASSES
): CanonicalizeResult<string> {
  const initialControlIssue = findDisallowedControlChar(input);
  if (initialControlIssue !== null) {
    return {
      ok: false,
      reasonCode: "EVASION_DETECTED",
      detail: initialControlIssue
    };
  }

  const effectivePasses = Math.max(1, maxPasses);
  let current = input;

  for (let pass = 0; pass < effectivePasses; pass += 1) {
    const passResult = decodePercentSinglePass(current);
    if (!passResult.ok) {
      return passResult;
    }

    current = passResult.value.decoded;
    const postDecodeControlIssue = findDisallowedControlChar(current);
    if (postDecodeControlIssue !== null) {
      return {
        ok: false,
        reasonCode: "EVASION_DETECTED",
        detail: postDecodeControlIssue
      };
    }

    if (!passResult.value.changed) {
      return {
        ok: true,
        value: current.normalize("NFC")
      };
    }
  }

  // Probe one additional pass: if it still changes, caller nested encodings beyond maxPasses.
  const overflowProbe = decodePercentSinglePass(current);
  if (!overflowProbe.ok) {
    return overflowProbe;
  }
  if (overflowProbe.value.changed) {
    return {
      ok: false,
      reasonCode: "EVASION_DETECTED",
      detail: `Nested percent-encoding depth exceeded maximum allowed passes (${effectivePasses}).`
    };
  }

  return {
    ok: true,
    value: current.normalize("NFC")
  };
}

/**
 * Recursively canonicalizes an unknown JSON value without mutating the original input.
 */
export function canonicalizeValue(
  value: unknown,
  maxPasses: number = DEFAULT_MAX_DECODE_PASSES
): CanonicalizeResult<unknown> {
  if (typeof value === "string") {
    return canonicalizeString(value, maxPasses);
  }

  if (Array.isArray(value)) {
    const normalizedItems: unknown[] = [];
    for (let i = 0; i < value.length; i += 1) {
      const itemResult = canonicalizeValue(value[i], maxPasses);
      if (!itemResult.ok) {
        return itemResult;
      }
      normalizedItems.push(itemResult.value);
    }
    return { ok: true, value: normalizedItems };
  }

  if (typeof value === "object" && value !== null) {
    const source = value as Record<string, unknown>;
    const normalizedObj: Record<string, unknown> = {};
    for (const [rawKey, rawVal] of Object.entries(source)) {
      const keyResult = canonicalizeString(rawKey, maxPasses);
      if (!keyResult.ok) {
        return keyResult;
      }
      const valResult = canonicalizeValue(rawVal, maxPasses);
      if (!valResult.ok) {
        return valResult;
      }
      normalizedObj[keyResult.value] = valResult.value;
    }
    return { ok: true, value: normalizedObj };
  }

  return { ok: true, value };
}

/**
 * Canonicalizes a key-value argument dictionary while leaving the raw input object untouched.
 */
export function canonicalizeRecord(
  record: Readonly<Record<string, unknown>>,
  maxPasses: number = DEFAULT_MAX_DECODE_PASSES
): CanonicalizeResult<Record<string, unknown>> {
  const result = canonicalizeValue(record, maxPasses);
  if (!result.ok) {
    return result;
  }
  return {
    ok: true,
    value: result.value as Record<string, unknown>
  };
}
