import { normalizePathSlashes } from "../protocol/canonicalizer.js";
import type { NormalizedMcpInvocation } from "../types/mcp.js";
import type { PathGuardConfig } from "../types/policy.js";
import type { GuardCheckResult } from "./payload-guard.js";

const DEFAULT_PATH_ARGUMENT_KEYS: readonly string[] = [
  "path",
  "file",
  "filepath",
  "filename",
  "dir",
  "directory",
  "folder",
  "cwd",
  "root",
  "source",
  "src",
  "dest",
  "destination",
  "targetpath",
  "outputpath",
  "inputpath"
];

const BUILTIN_SENSITIVE_BASENAMES: ReadonlySet<string> = new Set([
  ".env",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".htpasswd",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "authorized_keys",
  "known_hosts",
  "shadow",
  "passwd",
  "sudoers",
  "master.passwd",
  "sam",
  "ntds.dit"
]);

const BUILTIN_SENSITIVE_SEGMENTS: readonly string[] = [
  "/.ssh/",
  "/.aws/",
  "/.gnupg/",
  "/.kube/",
  "/.docker/config.json",
  "/.git/config",
  "/.git/credentials",
  "/etc/passwd",
  "/etc/shadow",
  "/etc/sudoers",
  "/proc/self/environ",
  "/proc/self/cmdline"
];

const BUILTIN_SENSITIVE_EXTENSIONS: readonly string[] = [
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".kdbx",
  ".tfstate"
];

function normalizeKeyIdentifier(key: string): string {
  return key.toLowerCase().replaceAll("_", "").replaceAll("-", "");
}

function isWindowsDrivePath(pathValue: string): boolean {
  if (pathValue.length < 2) {
    return false;
  }
  const first = pathValue.charCodeAt(0);
  const isAlpha =
    (first >= 65 && first <= 90) || (first >= 97 && first <= 122);
  return isAlpha && pathValue.charCodeAt(1) === 58 /* ':' */;
}

/**
 * Lexically resolves POSIX and Windows-normalized paths into canonical absolute form,
 * tracking whether `..` attempted to climb above filesystem root.
 */
export function resolveLexicalPath(
  rawPath: string,
  baseRoot?: string
): { readonly resolved: string; readonly escapedRoot: boolean } {
  let cleaned = normalizePathSlashes(rawPath.trim());

  if (cleaned.toLowerCase().startsWith("file://")) {
    cleaned = cleaned.slice("file://".length);
    if (cleaned.toLowerCase().startsWith("localhost/")) {
      cleaned = cleaned.slice("localhost".length);
    }
    // Normalize file:///C:/path -> C:/path
    if (cleaned.startsWith("/") && isWindowsDrivePath(cleaned.slice(1))) {
      cleaned = cleaned.slice(1);
    }
  }

  const isAbsolutePosix = cleaned.startsWith("/");
  const isAbsoluteWin = isWindowsDrivePath(cleaned);

  let workingPath = cleaned;
  if (!isAbsolutePosix && !isAbsoluteWin && baseRoot !== undefined) {
    const normalizedBase = normalizePathSlashes(baseRoot.trim());
    workingPath = normalizedBase.endsWith("/")
      ? `${normalizedBase}${cleaned}`
      : `${normalizedBase}/${cleaned}`;
  }

  let prefix = "/";
  let remainder = workingPath;

  if (isWindowsDrivePath(workingPath)) {
    prefix = `${workingPath.slice(0, 2).toLowerCase()}/`;
    remainder = workingPath.slice(2);
  } else if (workingPath.startsWith("/")) {
    prefix = "/";
    remainder = workingPath.slice(1);
  } else {
    prefix = "";
  }

  const parts = remainder.split("/");
  const stack: string[] = [];
  let escapedRoot = false;

  for (let i = 0; i < parts.length; i += 1) {
    const segment = parts[i];
    if (segment === undefined || segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      if (stack.length === 0) {
        escapedRoot = true;
      } else {
        stack.pop();
      }
      continue;
    }
    stack.push(segment);
  }

  const joined = `${prefix}${stack.join("/")}`;
  return {
    resolved: joined === "" ? "/" : joined,
    escapedRoot
  };
}

function containsRawTraversalTokens(value: string): boolean {
  const normalized = normalizePathSlashes(value);
  return (
    normalized === ".." ||
    normalized.startsWith("../") ||
    normalized.endsWith("/..") ||
    normalized.includes("/../")
  );
}

function isNonFileUrl(value: string): boolean {
  const lower = value.trim().toLowerCase();
  return lower.startsWith("http://") || lower.startsWith("https://");
}

/**
 * Enforces lexical Root-Jail containment and blocks access to sensitive credential dotfiles
 * across MCP resource URIs and nested tool call arguments.
 */
export class PathTraversalGuard {
  private readonly enabled: boolean;
  private readonly normalizedRoots: readonly string[];
  private readonly customBlockedPatterns: readonly string[];
  private readonly pathKeySet: ReadonlySet<string>;

  public constructor(config: PathGuardConfig) {
    this.enabled = config.enabled ?? true;
    this.normalizedRoots = config.allowedRoots.map(
      (root) => resolveLexicalPath(root).resolved
    );
    this.customBlockedPatterns = (config.blockedFilePatterns ?? []).map((p) =>
      normalizePathSlashes(p).toLowerCase()
    );

    const keys = new Set<string>(DEFAULT_PATH_ARGUMENT_KEYS);
    if (config.pathArgumentKeys !== undefined) {
      for (const customKey of config.pathArgumentKeys) {
        keys.add(normalizeKeyIdentifier(customKey));
      }
    }
    this.pathKeySet = keys;
  }

  public check(invocation: NormalizedMcpInvocation): GuardCheckResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    if (invocation.operationKind === "resource") {
      const target = invocation.target.trim();
      if (
        target.toLowerCase().startsWith("file://") ||
        target.startsWith("/") ||
        target.startsWith("~") ||
        containsRawTraversalTokens(target) ||
        isWindowsDrivePath(target)
      ) {
        const uriResult = this.inspectFilesystemCandidate(target, "uri");
        if (!uriResult.allowed) {
          return uriResult;
        }
      }
    }

    return this.walkArguments(invocation.canonicalArguments);
  }

  private walkArguments(node: unknown, currentKey?: string): GuardCheckResult {
    if (typeof node === "string") {
      const trimmed = node.trim();
      if (trimmed.length === 0 || isNonFileUrl(trimmed)) {
        return { allowed: true };
      }

      const isExplicitPathKey =
        currentKey !== undefined &&
        this.pathKeySet.has(normalizeKeyIdentifier(currentKey));
      const isFileUri = trimmed.toLowerCase().startsWith("file://");

      if (isExplicitPathKey || isFileUri) {
        return this.inspectFilesystemCandidate(
          trimmed,
          currentKey ?? "argument"
        );
      }

      // Even on arbitrary non-path keys, block explicit traversal sequences or sensitive credential paths.
      if (containsRawTraversalTokens(trimmed)) {
        return {
          allowed: false,
          reasonCode: "PATH_TRAVERSAL_BLOCKED",
          detail: `Directory traversal sequence detected in argument '${currentKey ?? "value"}'.`
        };
      }

      if (this.matchesSensitiveTarget(trimmed)) {
        return {
          allowed: false,
          reasonCode: "SENSITIVE_FILE_BLOCKED",
          detail: `Sensitive credential or system path detected in argument '${currentKey ?? "value"}'.`
        };
      }

      return { allowed: true };
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        const itemCheck = this.walkArguments(node[i], currentKey);
        if (!itemCheck.allowed) {
          return itemCheck;
        }
      }
      return { allowed: true };
    }

    if (typeof node === "object" && node !== null) {
      const record = node as Record<string, unknown>;
      for (const [key, val] of Object.entries(record)) {
        const entryCheck = this.walkArguments(val, key);
        if (!entryCheck.allowed) {
          return entryCheck;
        }
      }
    }

    return { allowed: true };
  }

  private inspectFilesystemCandidate(
    candidate: string,
    fieldName: string
  ): GuardCheckResult {
    const slashNormalized = normalizePathSlashes(candidate);

    if (slashNormalized === "~" || slashNormalized.startsWith("~/")) {
      return {
        allowed: false,
        reasonCode: "PATH_TRAVERSAL_BLOCKED",
        detail: `Home directory expansion ('~') in '${fieldName}' is disallowed.`
      };
    }

    if (this.matchesSensitiveTarget(slashNormalized)) {
      return {
        allowed: false,
        reasonCode: "SENSITIVE_FILE_BLOCKED",
        detail: `Access to sensitive file target in '${fieldName}' is blocked by security policy.`
      };
    }

    if (this.normalizedRoots.length === 0) {
      return {
        allowed: false,
        reasonCode: "PATH_TRAVERSAL_BLOCKED",
        detail: `Filesystem access in '${fieldName}' denied because allowedRoots is empty.`
      };
    }

    const defaultBase = this.normalizedRoots[0];
    const { resolved, escapedRoot } = resolveLexicalPath(
      slashNormalized,
      defaultBase
    );

    if (escapedRoot) {
      return {
        allowed: false,
        reasonCode: "PATH_TRAVERSAL_BLOCKED",
        detail: `Path '${fieldName}' attempted to traverse above filesystem root.`
      };
    }

    if (this.matchesSensitiveTarget(resolved)) {
      return {
        allowed: false,
        reasonCode: "SENSITIVE_FILE_BLOCKED",
        detail: `Resolved path in '${fieldName}' targets a restricted credential or system file.`
      };
    }

    const insideAllowedRoot = this.normalizedRoots.some((root) => {
      if (root === "/") {
        return resolved.startsWith("/");
      }
      return resolved === root || resolved.startsWith(`${root}/`);
    });

    if (!insideAllowedRoot) {
      return {
        allowed: false,
        reasonCode: "PATH_TRAVERSAL_BLOCKED",
        detail: `Resolved path '${resolved}' in '${fieldName}' escapes configured allowedRoots.`
      };
    }

    return { allowed: true };
  }

  private matchesSensitiveTarget(rawPath: string): boolean {
    const normalized = normalizePathSlashes(rawPath).toLowerCase();
    const padded = normalized.startsWith("/") ? normalized : `/${normalized}`;

    const segments = padded.split("/");
    const basename = segments[segments.length - 1] ?? "";

    if (BUILTIN_SENSITIVE_BASENAMES.has(basename)) {
      return true;
    }

    if (basename.startsWith(".env.") && basename !== ".env.example") {
      return true;
    }

    for (const ext of BUILTIN_SENSITIVE_EXTENSIONS) {
      if (basename.endsWith(ext)) {
        return true;
      }
    }

    for (const restrictedSegment of BUILTIN_SENSITIVE_SEGMENTS) {
      if (
        padded.includes(restrictedSegment) ||
        padded.endsWith(restrictedSegment.slice(0, -1))
      ) {
        return true;
      }
    }

    for (const custom of this.customBlockedPatterns) {
      if (custom.length > 0 && (normalized.includes(custom) || basename === custom)) {
        return true;
      }
    }

    return false;
  }
}
