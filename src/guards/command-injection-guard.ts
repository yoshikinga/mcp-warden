import type { NormalizedMcpInvocation } from "../types/mcp.js";
import type { CommandGuardConfig } from "../types/policy.js";
import type { GuardCheckResult } from "./payload-guard.js";

const DEFAULT_COMMAND_ARGUMENT_KEYS: readonly string[] = [
  "cmd",
  "command",
  "shell",
  "script",
  "exec",
  "executable",
  "bin",
  "binary",
  "args",
  "argv",
  "flags",
  "options",
  "subcommand",
  "branch",
  "ref",
  "revision",
  "tag",
  "host",
  "target"
];

const SHELL_ORIENTED_TOOL_PREFIXES: readonly string[] = [
  "exec",
  "shell",
  "bash",
  "sh",
  "cmd",
  "run",
  "terminal",
  "cli",
  "git",
  "docker",
  "kubectl",
  "ssh"
];

function normalizeKey(key: string): string {
  return key.toLowerCase().replaceAll("_", "").replaceAll("-", "");
}

function isHttpUrlWithoutShellTokens(value: string): boolean {
  const trimmed = value.trim();
  const lower = trimmed.toLowerCase();
  if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
    return false;
  }
  for (let i = 0; i < trimmed.length; i += 1) {
    const code = trimmed.charCodeAt(i);
    // Reject whitespace, newlines, semicolons, pipes, backticks, angle brackets
    if (
      code <= 32 ||
      code === 59 /* ; */ ||
      code === 96 /* ` */ ||
      code === 124 /* | */ ||
      code === 60 /* < */ ||
      code === 62 /* > */
    ) {
      return false;
    }
  }
  return !trimmed.includes("$(") && !trimmed.includes("${");
}

function containsNewline(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 10 || code === 13) {
      return true;
    }
  }
  return false;
}

/**
 * Inspects MCP tool arguments for shell command chaining, subshell expansions,
 * pipes, redirection operators, and newline injection vectors.
 */
export class CommandInjectionGuard {
  private readonly enabled: boolean;
  private readonly scanAllStrings: boolean;
  private readonly commandKeySet: ReadonlySet<string>;

  public constructor(config: CommandGuardConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.scanAllStrings = config.scanAllStrings ?? true;

    const keySet = new Set<string>(DEFAULT_COMMAND_ARGUMENT_KEYS);
    if (config.commandArgumentKeys !== undefined) {
      for (const custom of config.commandArgumentKeys) {
        keySet.add(normalizeKey(custom));
      }
    }
    this.commandKeySet = keySet;
  }

  public check(invocation: NormalizedMcpInvocation): GuardCheckResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    const lowerTarget = invocation.target.toLowerCase();
    const isShellOrientedTool = SHELL_ORIENTED_TOOL_PREFIXES.some(
      (prefix) =>
        lowerTarget === prefix ||
        lowerTarget.startsWith(`${prefix}:`) ||
        lowerTarget.startsWith(`${prefix}_`) ||
        lowerTarget.startsWith(`${prefix}-`) ||
        lowerTarget.startsWith(`${prefix}/`)
    );

    return this.inspectNode(
      invocation.canonicalArguments,
      undefined,
      isShellOrientedTool
    );
  }

  private inspectNode(
    node: unknown,
    currentKey: string | undefined,
    isShellTool: boolean
  ): GuardCheckResult {
    if (typeof node === "string") {
      const isCommandKey =
        currentKey !== undefined &&
        this.commandKeySet.has(normalizeKey(currentKey));
      const strictCommandContext = isCommandKey || isShellTool;

      if (!strictCommandContext && !this.scanAllStrings) {
        return { allowed: true };
      }

      return this.inspectStringValue(
        node,
        currentKey ?? "argument",
        strictCommandContext
      );
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        const result = this.inspectNode(node[i], currentKey, isShellTool);
        if (!result.allowed) {
          return result;
        }
      }
      return { allowed: true };
    }

    if (typeof node === "object" && node !== null) {
      const record = node as Record<string, unknown>;
      for (const [key, val] of Object.entries(record)) {
        const result = this.inspectNode(val, key, isShellTool);
        if (!result.allowed) {
          return result;
        }
      }
    }

    return { allowed: true };
  }

  private inspectStringValue(
    value: string,
    fieldName: string,
    strictCommandContext: boolean
  ): GuardCheckResult {
    if (value.length === 0) {
      return { allowed: true };
    }

    // Preserve valid query-string '&' inside clean HTTP(S) URLs so SsrfGuard can evaluate them.
    if (!strictCommandContext && isHttpUrlWithoutShellTokens(value)) {
      return { allowed: true };
    }

    if (value.includes("$(")) {
      return {
        allowed: false,
        reasonCode: "COMMAND_INJECTION_BLOCKED",
        detail: `Subshell command substitution '$()' detected in '${fieldName}'.`
      };
    }

    if (value.includes("${")) {
      return {
        allowed: false,
        reasonCode: "COMMAND_INJECTION_BLOCKED",
        detail: `Shell parameter expansion '\${}' detected in '${fieldName}'.`
      };
    }

    if (value.includes("`")) {
      return {
        allowed: false,
        reasonCode: "COMMAND_INJECTION_BLOCKED",
        detail: `Backtick command substitution detected in '${fieldName}'.`
      };
    }

    if (value.includes("&&") || value.includes("||")) {
      return {
        allowed: false,
        reasonCode: "COMMAND_INJECTION_BLOCKED",
        detail: `Logical shell chaining operator ('&&' or '||') detected in '${fieldName}'.`
      };
    }

    if (value.includes(";")) {
      return {
        allowed: false,
        reasonCode: "COMMAND_INJECTION_BLOCKED",
        detail: `Command separator ';' detected in '${fieldName}'.`
      };
    }

    if (value.includes("|")) {
      return {
        allowed: false,
        reasonCode: "COMMAND_INJECTION_BLOCKED",
        detail: `Shell pipe operator '|' detected in '${fieldName}'.`
      };
    }

    if (strictCommandContext) {
      if (containsNewline(value)) {
        return {
          allowed: false,
          reasonCode: "COMMAND_INJECTION_BLOCKED",
          detail: `Multiline newline/carriage-return injection detected in command argument '${fieldName}'.`
        };
      }

      if (value.includes(">") || value.includes("<")) {
        return {
          allowed: false,
          reasonCode: "COMMAND_INJECTION_BLOCKED",
          detail: `Shell stream redirection ('>' or '<') detected in command argument '${fieldName}'.`
        };
      }

      if (value.includes("&")) {
        return {
          allowed: false,
          reasonCode: "COMMAND_INJECTION_BLOCKED",
          detail: `Background execution operator '&' detected in command argument '${fieldName}'.`
        };
      }
    }

    return { allowed: true };
  }
}
