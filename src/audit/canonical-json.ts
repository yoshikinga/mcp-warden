/**
 * Produces a deterministic, lexicographically key-sorted JSON string representation
 * aligned with RFC 8785 (JSON Canonicalization Scheme) so cryptographic SHA-256 digests
 * remain identical across V8, JavaScriptCore, and SpiderMonkey runtimes.
 */
export function canonicalizeJson(value: unknown): string {
  return serializeCanonicalNode(value, new Set<object>());
}

function serializeCanonicalNode(
  value: unknown,
  ancestors: Set<object>
): string {
  if (value === null || value === undefined) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return "null";
    }
    if (Object.is(value, -0)) {
      return "0";
    }
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "bigint") {
    return JSON.stringify(value.toString());
  }

  if (typeof value !== "object") {
    return "null";
  }

  if (ancestors.has(value)) {
    throw new TypeError("Cannot canonicalize circular JSON structure.");
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const serializedItems: string[] = [];
      for (let i = 0; i < value.length; i += 1) {
        const item = value[i];
        serializedItems.push(
          serializeCanonicalNode(item === undefined ? null : item, ancestors)
        );
      }
      return `[${serializedItems.join(",")}]`;
    }

    const record = value as Record<string, unknown>;
    const sortedKeys = Object.keys(record).sort();
    const serializedPairs: string[] = [];

    for (let i = 0; i < sortedKeys.length; i += 1) {
      const key = sortedKeys[i];
      if (key === undefined) {
        continue;
      }
      const propValue = record[key];
      if (propValue === undefined || typeof propValue === "function" || typeof propValue === "symbol") {
        continue;
      }
      const encodedKey = JSON.stringify(key);
      const encodedVal = serializeCanonicalNode(propValue, ancestors);
      serializedPairs.push(`${encodedKey}:${encodedVal}`);
    }

    return `{${serializedPairs.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}
