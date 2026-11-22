import type {
  EgressAction,
  EgressInspectionResult,
  EgressSecretConfig,
  SecretDetectorKind,
  SecretFinding
} from "../types/v1-1.js";

const DEFAULT_REPLACEMENT_MASK = "[REDACTED_SECRET]";
const DEFAULT_MAX_SCAN_DEPTH = 16;

const AWS_KEY_PREFIXES: readonly string[] = [
  "AKIA",
  "ASIA",
  "AGPA",
  "AIDA",
  "AROA"
];

const GITHUB_SHORT_PREFIXES: readonly string[] = [
  "ghp_",
  "gho_",
  "ghu_",
  "ghs_",
  "ghr_"
];

const SLACK_PREFIXES: readonly string[] = [
  "xoxb-",
  "xoxp-",
  "xoxa-",
  "xapp-"
];

const DB_URI_SCHEMES: readonly string[] = [
  "postgresql://",
  "postgres://",
  "mongodb+srv://",
  "mongodb://",
  "mysql://",
  "rediss://",
  "redis://",
  "amqp://"
];

interface SecretSpan {
  readonly start: number;
  readonly end: number;
  readonly kind: SecretDetectorKind;
  readonly preview: string;
}

function isUpperAlphaNum(code: number): boolean {
  return (code >= 65 && code <= 90) || (code >= 48 && code <= 57);
}

function isAlphaNum(code: number): boolean {
  return (
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57)
  );
}

function isBase64UrlChar(code: number): boolean {
  return isAlphaNum(code) || code === 45 /* '-' */ || code === 95 /* '_' */;
}

function isUriStopChar(code: number): boolean {
  return (
    code <= 32 ||
    code === 34 /* '"' */ ||
    code === 39 /* "'" */ ||
    code === 47 /* '/' */ ||
    code === 63 /* '?' */ ||
    code === 35 /* '#' */
  );
}

function buildSafePreview(rawSlice: string): string {
  const prefixLen = Math.min(4, rawSlice.length);
  return `${rawSlice.slice(0, prefixLen)}****`;
}

function scanPrefixedTokenSpans(params: {
  readonly text: string;
  readonly prefix: string;
  readonly minBodyLength: number;
  readonly maxBodyLength?: number;
  readonly allowUnderscore: boolean;
  readonly allowHyphen: boolean;
  readonly kind: SecretDetectorKind;
  readonly sink: SecretSpan[];
}): void {
  const {
    text,
    prefix,
    minBodyLength,
    maxBodyLength,
    allowUnderscore,
    allowHyphen,
    kind,
    sink
  } = params;

  let searchFrom = 0;
  while (searchFrom < text.length) {
    const idx = text.indexOf(prefix, searchFrom);
    if (idx === -1) {
      break;
    }

    const leftOk = idx === 0 || !isAlphaNum(text.charCodeAt(idx - 1));
    const bodyStart = idx + prefix.length;
    let cursor = bodyStart;

    while (cursor < text.length) {
      const code = text.charCodeAt(cursor);
      const validChar =
        isAlphaNum(code) ||
        (allowUnderscore && code === 95) ||
        (allowHyphen && code === 45);
      if (!validChar) {
        break;
      }
      cursor += 1;
    }

    const bodyLen = cursor - bodyStart;
    const withinMax =
      maxBodyLength === undefined ? true : bodyLen <= maxBodyLength;

    if (leftOk && bodyLen >= minBodyLength && withinMax) {
      sink.push({
        start: idx,
        end: cursor,
        kind,
        preview: buildSafePreview(prefix)
      });
      searchFrom = cursor;
    } else {
      searchFrom = bodyStart;
    }
  }
}

function scanAwsAccessKeys(text: string, sink: SecretSpan[]): void {
  for (let p = 0; p < AWS_KEY_PREFIXES.length; p += 1) {
    const prefix = AWS_KEY_PREFIXES[p];
    if (prefix === undefined) {
      continue;
    }

    let searchFrom = 0;
    while (searchFrom < text.length) {
      const idx = text.indexOf(prefix, searchFrom);
      if (idx === -1) {
        break;
      }

      const end = idx + 20;
      const leftOk = idx === 0 || !isAlphaNum(text.charCodeAt(idx - 1));
      const rightOk =
        end === text.length ||
        (end < text.length && !isAlphaNum(text.charCodeAt(end)));

      if (leftOk && end <= text.length && rightOk) {
        let allUpper = true;
        for (let c = idx + 4; c < end; c += 1) {
          if (!isUpperAlphaNum(text.charCodeAt(c))) {
            allUpper = false;
            break;
          }
        }

        if (allUpper) {
          sink.push({
            start: idx,
            end,
            kind: "AWS_ACCESS_KEY",
            preview: `${prefix}****`
          });
          searchFrom = end;
          continue;
        }
      }

      searchFrom = idx + 4;
    }
  }
}

function scanPemPrivateKeys(text: string, sink: SecretSpan[]): void {
  const beginMarker = "-----BEGIN ";
  const endMarker = "-----END ";
  let searchFrom = 0;

  while (searchFrom < text.length) {
    const beginIdx = text.indexOf(beginMarker, searchFrom);
    if (beginIdx === -1) {
      break;
    }

    const headerDashesEnd = text.indexOf("-----", beginIdx + beginMarker.length);
    if (headerDashesEnd === -1) {
      break;
    }

    const label = text.slice(beginIdx + beginMarker.length, headerDashesEnd).trim();
    if (!label.endsWith("PRIVATE KEY")) {
      searchFrom = headerDashesEnd + 5;
      continue;
    }

    const footerStart = text.indexOf(endMarker, headerDashesEnd + 5);
    let blockEnd = text.length;
    if (footerStart !== -1) {
      const footerClose = text.indexOf("-----", footerStart + endMarker.length);
      blockEnd = footerClose !== -1 ? footerClose + 5 : text.length;
    }

    sink.push({
      start: beginIdx,
      end: blockEnd,
      kind: "PRIVATE_KEY_PEM",
      preview: "PEM_KEY****"
    });

    searchFrom = blockEnd;
  }
}

function scanJwtTokens(text: string, sink: SecretSpan[]): void {
  let searchFrom = 0;
  while (searchFrom < text.length) {
    const idx = text.indexOf("eyJ", searchFrom);
    if (idx === -1) {
      break;
    }

    if (idx > 0 && isBase64UrlChar(text.charCodeAt(idx - 1))) {
      searchFrom = idx + 3;
      continue;
    }

    let dot1 = idx + 3;
    while (dot1 < text.length && isBase64UrlChar(text.charCodeAt(dot1))) {
      dot1 += 1;
    }

    if (
      dot1 - idx < 8 ||
      dot1 >= text.length ||
      text.charCodeAt(dot1) !== 46 /* '.' */ ||
      !text.startsWith("eyJ", dot1 + 1)
    ) {
      searchFrom = idx + 3;
      continue;
    }

    let dot2 = dot1 + 4;
    while (dot2 < text.length && isBase64UrlChar(text.charCodeAt(dot2))) {
      dot2 += 1;
    }

    if (
      dot2 - (dot1 + 1) < 8 ||
      dot2 >= text.length ||
      text.charCodeAt(dot2) !== 46 /* '.' */
    ) {
      searchFrom = dot1 + 1;
      continue;
    }

    let sigEnd = dot2 + 1;
    while (sigEnd < text.length && isBase64UrlChar(text.charCodeAt(sigEnd))) {
      sigEnd += 1;
    }

    if (sigEnd - (dot2 + 1) >= 8) {
      sink.push({
        start: idx,
        end: sigEnd,
        kind: "JWT_BEARER",
        preview: "eyJ****"
      });
      searchFrom = sigEnd;
    } else {
      searchFrom = dot2 + 1;
    }
  }
}

function scanDatabaseCredentialUris(text: string, sink: SecretSpan[]): void {
  const lower = text.toLowerCase();

  for (let s = 0; s < DB_URI_SCHEMES.length; s += 1) {
    const scheme = DB_URI_SCHEMES[s];
    if (scheme === undefined) {
      continue;
    }

    let searchFrom = 0;
    while (searchFrom < lower.length) {
      const idx = lower.indexOf(scheme, searchFrom);
      if (idx === -1) {
        break;
      }

      const authStart = idx + scheme.length;
      let authEnd = authStart;
      while (authEnd < text.length && !isUriStopChar(text.charCodeAt(authEnd))) {
        authEnd += 1;
      }

      const authority = text.slice(authStart, authEnd);
      const atOffset = authority.lastIndexOf("@");
      const colonOffset = atOffset !== -1 ? authority.indexOf(":") : -1;

      if (colonOffset !== -1 && atOffset !== -1 && colonOffset < atOffset) {
        const passwordStart = authStart + colonOffset + 1;
        const passwordEnd = authStart + atOffset;
        const passwordCandidate = text.slice(passwordStart, passwordEnd);

        if (
          passwordCandidate.length > 0 &&
          !passwordCandidate.includes("REDACTED") &&
          passwordCandidate !== "****"
        ) {
          sink.push({
            start: passwordStart,
            end: passwordEnd,
            kind: "DATABASE_URI_CREDENTIALS",
            preview: `${scheme.slice(0, Math.min(4, scheme.length))}****`
          });
        }
      }

      searchFrom = Math.max(authStart, authEnd);
    }
  }
}

function mergeSecretSpans(spans: readonly SecretSpan[]): readonly SecretSpan[] {
  if (spans.length <= 1) {
    return spans;
  }

  const sorted = [...spans].sort((a, b) =>
    a.start !== b.start ? a.start - b.start : b.end - a.end
  );

  const merged: SecretSpan[] = [];
  for (let i = 0; i < sorted.length; i += 1) {
    const current = sorted[i];
    if (current === undefined) {
      continue;
    }
    const last = merged[merged.length - 1];
    if (last === undefined || current.start > last.end) {
      merged.push(current);
    } else if (current.end > last.end) {
      merged[merged.length - 1] = {
        start: last.start,
        end: current.end,
        kind: last.kind,
        preview: last.preview
      };
    }
  }

  return merged;
}

/**
 * Outbound Egress Guard that scans MCP tool/resource responses in linear time
 * to redact or block leaked cloud keys, tokens, PEM private keys, JWTs, and DB credentials
 * before they reach the AI Agent's context window.
 */
export class EgressSecretGuard {
  private readonly enabled: boolean;
  private readonly action: EgressAction;
  private readonly replacementMask: string;
  private readonly detectJwtTokens: boolean;
  private readonly customSecretPrefixes: readonly string[];
  private readonly maxScanDepth: number;

  public constructor(config: EgressSecretConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.action = config.action ?? "REDACT";
    this.replacementMask = config.replacementMask ?? DEFAULT_REPLACEMENT_MASK;
    this.detectJwtTokens = config.detectJwtTokens ?? true;
    this.customSecretPrefixes = (config.customSecretPrefixes ?? []).filter(
      (prefix) => prefix.trim().length >= 3
    );
    this.maxScanDepth = Math.max(1, config.maxScanDepth ?? DEFAULT_MAX_SCAN_DEPTH);
  }

  /**
   * Inspects an outbound MCP response or result payload without mutating the caller's object.
   */
  public inspect<TPayload = unknown>(
    payload: TPayload
  ): EgressInspectionResult<TPayload> {
    if (!this.enabled) {
      return {
        allowed: true,
        mutated: false,
        sanitizedPayload: payload,
        findings: [],
        reasonCode: null,
        detail: "EgressSecretGuard disabled."
      };
    }

    const findings: SecretFinding[] = [];
    const transformed = this.walkAndSanitize(
      payload,
      "response",
      0,
      new Set<object>(),
      findings
    );

    if (findings.length === 0) {
      return {
        allowed: true,
        mutated: false,
        sanitizedPayload: payload,
        findings: [],
        reasonCode: null,
        detail: "No outbound secrets detected."
      };
    }

    if (this.action === "BLOCK") {
      return {
        allowed: false,
        mutated: false,
        sanitizedPayload: payload,
        findings,
        reasonCode: "EGRESS_SECRET_BLOCKED",
        detail: `Blocked outbound MCP response containing ${findings.length} credential leak(s).`
      };
    }

    return {
      allowed: true,
      mutated: true,
      sanitizedPayload: transformed as TPayload,
      findings,
      reasonCode: "EGRESS_SECRET_REDACTED",
      detail: `Redacted ${findings.length} credential leak(s) from outbound MCP response.`
    };
  }

  private walkAndSanitize(
    node: unknown,
    currentPath: string,
    depth: number,
    ancestors: Set<object>,
    findings: SecretFinding[]
  ): unknown {
    if (depth > this.maxScanDepth) {
      return node;
    }

    if (typeof node === "string") {
      return this.inspectString(node, currentPath, findings);
    }

    if (typeof node !== "object" || node === null) {
      return node;
    }

    if (ancestors.has(node)) {
      return node;
    }

    ancestors.add(node);
    try {
      if (Array.isArray(node)) {
        let arrayChanged = false;
        const nextArr: unknown[] = new Array<unknown>(node.length);

        for (let i = 0; i < node.length; i += 1) {
          const item = node[i];
          const nextItem = this.walkAndSanitize(
            item,
            `${currentPath}[${i}]`,
            depth + 1,
            ancestors,
            findings
          );
          if (nextItem !== item) {
            arrayChanged = true;
          }
          nextArr[i] = nextItem;
        }

        return arrayChanged ? nextArr : node;
      }

      const record = node as Record<string, unknown>;
      let objectChanged = false;
      const nextObj: Record<string, unknown> = {};

      for (const [key, val] of Object.entries(record)) {
        const nextVal = this.walkAndSanitize(
          val,
          `${currentPath}.${key}`,
          depth + 1,
          ancestors,
          findings
        );
        if (nextVal !== val) {
          objectChanged = true;
        }
        nextObj[key] = nextVal;
      }

      return objectChanged ? nextObj : node;
    } finally {
      ancestors.delete(node);
    }
  }

  private inspectString(
    text: string,
    fieldPath: string,
    findings: SecretFinding[]
  ): string {
    if (text.length < 8) {
      return text;
    }

    const rawSpans: SecretSpan[] = [];

    scanPemPrivateKeys(text, rawSpans);
    scanAwsAccessKeys(text, rawSpans);

    for (let i = 0; i < GITHUB_SHORT_PREFIXES.length; i += 1) {
      const ghPrefix = GITHUB_SHORT_PREFIXES[i];
      if (ghPrefix !== undefined) {
        scanPrefixedTokenSpans({
          text,
          prefix: ghPrefix,
          minBodyLength: 30,
          allowUnderscore: false,
          allowHyphen: false,
          kind: "GITHUB_TOKEN",
          sink: rawSpans
        });
      }
    }

    scanPrefixedTokenSpans({
      text,
      prefix: "github_pat_",
      minBodyLength: 22,
      allowUnderscore: true,
      allowHyphen: false,
      kind: "GITHUB_TOKEN",
      sink: rawSpans
    });

    scanPrefixedTokenSpans({
      text,
      prefix: "sk-ant-",
      minBodyLength: 20,
      allowUnderscore: true,
      allowHyphen: true,
      kind: "ANTHROPIC_KEY",
      sink: rawSpans
    });

    for (const oaiPrefix of ["sk-proj-", "sk-svcacct-", "sk-live-"]) {
      scanPrefixedTokenSpans({
        text,
        prefix: oaiPrefix,
        minBodyLength: 20,
        allowUnderscore: true,
        allowHyphen: true,
        kind: "OPENAI_OR_API_KEY",
        sink: rawSpans
      });
    }

    for (const stripePrefix of ["sk_live_", "rk_live_"]) {
      scanPrefixedTokenSpans({
        text,
        prefix: stripePrefix,
        minBodyLength: 16,
        allowUnderscore: false,
        allowHyphen: false,
        kind: "STRIPE_LIVE_KEY",
        sink: rawSpans
      });
    }

    for (let i = 0; i < SLACK_PREFIXES.length; i += 1) {
      const slackPrefix = SLACK_PREFIXES[i];
      if (slackPrefix !== undefined) {
        scanPrefixedTokenSpans({
          text,
          prefix: slackPrefix,
          minBodyLength: 16,
          allowUnderscore: false,
          allowHyphen: true,
          kind: "SLACK_TOKEN",
          sink: rawSpans
        });
      }
    }

    scanPrefixedTokenSpans({
      text,
      prefix: "AIza",
      minBodyLength: 35,
      maxBodyLength: 35,
      allowUnderscore: true,
      allowHyphen: true,
      kind: "GOOGLE_API_KEY",
      sink: rawSpans
    });

    if (this.detectJwtTokens) {
      scanJwtTokens(text, rawSpans);
    }

    scanDatabaseCredentialUris(text, rawSpans);

    for (let i = 0; i < this.customSecretPrefixes.length; i += 1) {
      const customPrefix = this.customSecretPrefixes[i];
      if (customPrefix !== undefined) {
        scanPrefixedTokenSpans({
          text,
          prefix: customPrefix,
          minBodyLength: 8,
          allowUnderscore: true,
          allowHyphen: true,
          kind: "CUSTOM_PREFIX",
          sink: rawSpans
        });
      }
    }

    if (rawSpans.length === 0) {
      return text;
    }

    const merged = mergeSecretSpans(rawSpans);
    let cursor = 0;
    let output = "";

    for (let i = 0; i < merged.length; i += 1) {
      const span = merged[i];
      if (span === undefined) {
        continue;
      }
      findings.push({
        kind: span.kind,
        fieldPath,
        preview: span.preview
      });

      if (this.action === "REDACT") {
        output += text.slice(cursor, span.start);
        output += this.replacementMask;
        cursor = span.end;
      }
    }

    if (this.action === "BLOCK") {
      return text;
    }

    output += text.slice(cursor);
    return output;
  }
}
