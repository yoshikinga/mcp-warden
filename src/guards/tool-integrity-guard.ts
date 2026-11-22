import { canonicalizeJson } from "../audit/canonical-json.js";
import { computeSha256Hex } from "../audit/hash-chain.js";
import type {
  McpToolDefinition,
  ToolIntegrityCheckResult,
  ToolIntegrityConfig
} from "../types/v1-1.js";
import { UnicodeTrojanGuard } from "./unicode-trojan-guard.js";

const DEFAULT_MAX_TRACKED_SERVERS = 500;

/**
 * High-signal covert prompt-injection phrases found in poisoned MCP `tools/list` metadata.
 */
const POISONED_DESCRIPTION_MARKERS: readonly string[] = [
  "<important>",
  "</important>",
  "<system>",
  "</system>",
  "[system]",
  "ignore previous instructions",
  "ignore all prior instructions",
  "disregard previous instructions",
  "do not mention this",
  "do not tell the user",
  "hide this action",
  "silently read",
  "exfiltrate",
  "~/.ssh",
  "/etc/passwd",
  "/etc/shadow",
  "169.254.169.254"
];

function constantTimeDigestEqual(a: string, b: string): boolean {
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
 * Computes a deterministic SHA-256 fingerprint over a tool's canonical `{ name, description, inputSchema }`.
 */
export async function computeToolFingerprint(
  tool: McpToolDefinition
): Promise<string> {
  const canonicalPayload = canonicalizeJson({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? {}
  });
  return computeSha256Hex(canonicalPayload);
}

/**
 * Protects MCP hosts and gateways against Tool Poisoning (malicious prompt directives hidden inside
 * tool descriptions/schemas) and Rug-Pull attacks (upstream servers mutating tool schemas mid-session).
 */
export class ToolIntegrityGuard {
  private readonly enabled: boolean;
  private readonly detectDescriptionInjection: boolean;
  private readonly pinOnFirstObservation: boolean;
  private readonly allowDynamicNewTools: boolean;
  private readonly maxTrackedServers: number;
  private readonly trustedFingerprints: Readonly<Record<string, string>>;
  private readonly unicodeScanner: UnicodeTrojanGuard;
  private readonly pinnedCatalogs = new Map<string, ReadonlyMap<string, string>>();

  public constructor(config: ToolIntegrityConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.detectDescriptionInjection = config.detectDescriptionInjection ?? true;
    this.pinOnFirstObservation = config.pinOnFirstObservation ?? true;
    this.allowDynamicNewTools = config.allowDynamicNewTools ?? false;
    this.maxTrackedServers = Math.max(
      1,
      config.maxTrackedServers ?? DEFAULT_MAX_TRACKED_SERVERS
    );
    this.trustedFingerprints = { ...(config.trustedFingerprints ?? {}) };
    this.unicodeScanner = new UnicodeTrojanGuard();
  }

  /**
   * Inspects and cryptographically verifies an MCP `tools/list` catalog for a given `serverId`.
   */
  public async inspectToolsList(
    serverId: string,
    tools: readonly McpToolDefinition[]
  ): Promise<ToolIntegrityCheckResult> {
    const computedFingerprints: Record<string, string> = {};

    for (let i = 0; i < tools.length; i += 1) {
      const tool = tools[i];
      if (tool === undefined) {
        continue;
      }
      computedFingerprints[tool.name] = await computeToolFingerprint(tool);
    }

    if (!this.enabled) {
      return {
        allowed: true,
        serverId,
        newlyPinned: false,
        fingerprints: computedFingerprints
      };
    }

    // Step 1: Scan descriptions and nested schema strings for Tool Poisoning & Unicode smuggling
    if (this.detectDescriptionInjection) {
      for (let i = 0; i < tools.length; i += 1) {
        const tool = tools[i];
        if (tool === undefined) {
          continue;
        }
        const poisonIssue = this.detectPoisoningInTool(tool);
        if (poisonIssue !== null) {
          return {
            allowed: false,
            serverId,
            reasonCode: "TOOL_POISONING_DETECTED",
            violatingToolName: tool.name,
            detail: poisonIssue,
            fingerprints: computedFingerprints
          };
        }
      }
    }

    // Step 2: Verify static pre-trusted SHA-256 supply-chain fingerprints if configured
    for (let i = 0; i < tools.length; i += 1) {
      const tool = tools[i];
      if (tool === undefined) {
        continue;
      }
      const expectedStatic = this.trustedFingerprints[tool.name];
      const actualHash = computedFingerprints[tool.name];
      if (
        expectedStatic !== undefined &&
        actualHash !== undefined &&
        !constantTimeDigestEqual(actualHash, expectedStatic.toLowerCase())
      ) {
        return {
          allowed: false,
          serverId,
          reasonCode: "TOOL_RUG_PULL_DETECTED",
          violatingToolName: tool.name,
          detail: `Tool '${tool.name}' on server '${serverId}' failed static SHA-256 fingerprint verification.`,
          fingerprints: computedFingerprints
        };
      }
    }

    // Step 3: Dynamic TOFU (Trust-On-First-Use) SHA-256 catalog pinning against mid-session Rug-Pulls
    const existingPin = this.pinnedCatalogs.get(serverId);
    if (existingPin === undefined) {
      if (this.pinOnFirstObservation) {
        this.pinServerCatalog(serverId, computedFingerprints);
        return {
          allowed: true,
          serverId,
          newlyPinned: true,
          fingerprints: computedFingerprints
        };
      }

      return {
        allowed: true,
        serverId,
        newlyPinned: false,
        fingerprints: computedFingerprints
      };
    }

    // Refresh LRU order for active serverId
    this.pinnedCatalogs.delete(serverId);
    this.pinnedCatalogs.set(serverId, existingPin);

    const updatedPin = new Map<string, string>(existingPin);

    for (let i = 0; i < tools.length; i += 1) {
      const tool = tools[i];
      if (tool === undefined) {
        continue;
      }
      const currentHash = computedFingerprints[tool.name];
      const pinnedHash = existingPin.get(tool.name);

      if (pinnedHash === undefined) {
        if (!this.allowDynamicNewTools) {
          return {
            allowed: false,
            serverId,
            reasonCode: "TOOL_RUG_PULL_DETECTED",
            violatingToolName: tool.name,
            detail: `Unannounced dynamic tool '${tool.name}' appeared on pinned server '${serverId}'.`,
            fingerprints: computedFingerprints
          };
        }
        if (currentHash !== undefined) {
          updatedPin.set(tool.name, currentHash);
        }
        continue;
      }

      if (
        currentHash === undefined ||
        !constantTimeDigestEqual(currentHash, pinnedHash)
      ) {
        return {
          allowed: false,
          serverId,
          reasonCode: "TOOL_RUG_PULL_DETECTED",
          violatingToolName: tool.name,
          detail: `MCP Rug-Pull detected: tool '${tool.name}' on server '${serverId}' mutated its description or inputSchema after pinning.`,
          fingerprints: computedFingerprints
        };
      }
    }

    if (updatedPin.size !== existingPin.size) {
      this.pinnedCatalogs.set(serverId, updatedPin);
    }

    return {
      allowed: true,
      serverId,
      newlyPinned: false,
      fingerprints: computedFingerprints
    };
  }

  public getTrackedServerCount(): number {
    return this.pinnedCatalogs.size;
  }

  public clearServerPin(serverId: string): void {
    this.pinnedCatalogs.delete(serverId);
  }

  public resetAllPins(): void {
    this.pinnedCatalogs.clear();
  }

  private pinServerCatalog(
    serverId: string,
    fingerprints: Readonly<Record<string, string>>
  ): void {
    if (this.pinnedCatalogs.size >= this.maxTrackedServers) {
      const oldestServer = this.pinnedCatalogs.keys().next().value;
      if (oldestServer !== undefined) {
        this.pinnedCatalogs.delete(oldestServer);
      }
    }
    this.pinnedCatalogs.set(serverId, new Map(Object.entries(fingerprints)));
  }

  private detectPoisoningInTool(tool: McpToolDefinition): string | null {
    const unicodeCheck = this.unicodeScanner.scanValue(
      {
        name: tool.name,
        description: tool.description ?? "",
        inputSchema: tool.inputSchema ?? {}
      },
      `tool(${tool.name})`
    );

    if (!unicodeCheck.allowed) {
      return `Hidden Unicode smuggling in tool '${tool.name}': ${unicodeCheck.detail}`;
    }

    const textsToInspect: string[] = [];
    if (tool.description !== undefined) {
      textsToInspect.push(tool.description);
    }
    if (tool.inputSchema !== undefined) {
      this.collectSchemaStrings(tool.inputSchema, textsToInspect);
    }

    for (let i = 0; i < textsToInspect.length; i += 1) {
      const rawText = textsToInspect[i];
      if (rawText === undefined || rawText.length === 0) {
        continue;
      }
      const lower = rawText.toLowerCase();
      for (let m = 0; m < POISONED_DESCRIPTION_MARKERS.length; m += 1) {
        const marker = POISONED_DESCRIPTION_MARKERS[m];
        if (marker !== undefined && lower.includes(marker)) {
          return `Covert prompt-injection marker '${marker}' detected in metadata of tool '${tool.name}'.`;
        }
      }
    }

    return null;
  }

  private collectSchemaStrings(node: unknown, sink: string[]): void {
    const stack: unknown[] = [node];
    const visited = new Set<object>();

    while (stack.length > 0) {
      const current = stack.pop();
      if (current === undefined || current === null) {
        continue;
      }
      if (typeof current === "string") {
        sink.push(current);
        continue;
      }
      if (typeof current !== "object") {
        continue;
      }
      if (visited.has(current)) {
        continue;
      }
      visited.add(current);

      if (Array.isArray(current)) {
        for (let i = 0; i < current.length; i += 1) {
          stack.push(current[i]);
        }
        continue;
      }

      const record = current as Record<string, unknown>;
      for (const val of Object.values(record)) {
        stack.push(val);
      }
    }
  }
}
