import type { NormalizedMcpInvocation } from "../types/mcp.js";
import type { SsrfGuardConfig } from "../types/policy.js";
import type { GuardCheckResult } from "./payload-guard.js";

const DEFAULT_ALLOWED_PROTOCOLS: readonly string[] = ["https:", "http:"];

const EXPLICIT_URL_KEYS: ReadonlySet<string> = new Set([
  "url",
  "endpoint",
  "href",
  "webhook",
  "webhookurl",
  "callback",
  "callbackurl",
  "targeturl",
  "requesturl",
  "origin",
  "proxy"
]);

const DANGEROUS_SCHEME_PREFIXES: readonly string[] = [
  "gopher:",
  "dict:",
  "ftp:",
  "ftps:",
  "ldap:",
  "ldaps:",
  "tftp:",
  "javascript:",
  "vbscript:",
  "data:",
  "jar:",
  "netdoc:"
];

const CLOUD_METADATA_HOSTNAMES: ReadonlySet<string> = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal"
]);

interface Ipv4Cidr {
  readonly network: number;
  readonly prefix: number;
  readonly label: string;
}

function ipv4ToUint32(a: number, b: number, c: number, d: number): number {
  return (((a << 24) | (b << 16) | (c << 8) | d) >>> 0);
}

const CLOUD_METADATA_IPV4_CIDRS: readonly Ipv4Cidr[] = [
  {
    network: ipv4ToUint32(169, 254, 169, 254),
    prefix: 32,
    label: "Cloud IMDS (169.254.169.254)"
  },
  {
    network: ipv4ToUint32(169, 254, 170, 2),
    prefix: 32,
    label: "ECS Task Metadata (169.254.170.2)"
  },
  {
    network: ipv4ToUint32(100, 100, 100, 200),
    prefix: 32,
    label: "Alibaba Cloud Metadata (100.100.100.200)"
  }
];

const PRIVATE_IPV4_CIDRS: readonly Ipv4Cidr[] = [
  { network: ipv4ToUint32(0, 0, 0, 0), prefix: 8, label: "Unspecified 0.0.0.0/8" },
  { network: ipv4ToUint32(10, 0, 0, 0), prefix: 8, label: "RFC1918 10.0.0.0/8" },
  { network: ipv4ToUint32(100, 64, 0, 0), prefix: 10, label: "CGNAT 100.64.0.0/10" },
  { network: ipv4ToUint32(127, 0, 0, 0), prefix: 8, label: "Loopback 127.0.0.0/8" },
  { network: ipv4ToUint32(169, 254, 0, 0), prefix: 16, label: "Link-Local 169.254.0.0/16" },
  { network: ipv4ToUint32(172, 16, 0, 0), prefix: 12, label: "RFC1918 172.16.0.0/12" },
  { network: ipv4ToUint32(192, 0, 0, 0), prefix: 24, label: "IETF 192.0.0.0/24" },
  { network: ipv4ToUint32(192, 168, 0, 0), prefix: 16, label: "RFC1918 192.168.0.0/16" },
  { network: ipv4ToUint32(198, 18, 0, 0), prefix: 15, label: "Benchmark 198.18.0.0/15" },
  { network: ipv4ToUint32(224, 0, 0, 0), prefix: 4, label: "Multicast 224.0.0.0/4" },
  { network: ipv4ToUint32(240, 0, 0, 0), prefix: 4, label: "Reserved 240.0.0.0/4" }
];

function isIpv4InCidr(ip: number, cidr: Ipv4Cidr): boolean {
  if (cidr.prefix === 0) {
    return true;
  }
  const mask = (0xffffffff << (32 - cidr.prefix)) >>> 0;
  return ((ip & mask) >>> 0) === ((cidr.network & mask) >>> 0);
}

/**
 * Parses dotted-decimal IPv4 string into an unsigned 32-bit integer.
 */
export function parseIpv4(host: string): number | null {
  const parts = host.split(".");
  if (parts.length !== 4) {
    return null;
  }

  const octets: number[] = [];
  for (let i = 0; i < 4; i += 1) {
    const part = parts[i];
    if (part === undefined || part.length === 0 || part.length > 3) {
      return null;
    }
    for (let j = 0; j < part.length; j += 1) {
      const code = part.charCodeAt(j);
      if (code < 48 || code > 57) {
        return null;
      }
    }
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) {
      return null;
    }
    octets.push(num);
  }

  return ipv4ToUint32(
    octets[0] ?? 0,
    octets[1] ?? 0,
    octets[2] ?? 0,
    octets[3] ?? 0
  );
}

/**
 * Parses canonical or compressed IPv6 text (without surrounding brackets) into 8 x 16-bit groups.
 * Handles embedded dotted IPv4 tails as well as URL-normalized hexadecimal IPv4-mapped tails.
 */
export function parseIpv6(rawHost: string): readonly number[] | null {
  let host = rawHost.toLowerCase();
  const zoneIdx = host.indexOf("%");
  if (zoneIdx !== -1) {
    host = host.slice(0, zoneIdx);
  }

  if (!host.includes(":")) {
    return null;
  }

  const doubleColonParts = host.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }

  const parseSegmentList = (segmentStr: string, isRightTail: boolean): number[] | null => {
    if (segmentStr.length === 0) {
      return [];
    }
    const tokens = segmentStr.split(":");
    const groups: number[] = [];

    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (token === undefined || token.length === 0) {
        return null;
      }

      if (isRightTail && i === tokens.length - 1 && token.includes(".")) {
        const ipv4 = parseIpv4(token);
        if (ipv4 === null) {
          return null;
        }
        groups.push((ipv4 >>> 16) & 0xffff);
        groups.push(ipv4 & 0xffff);
        continue;
      }

      if (token.length > 4) {
        return null;
      }
      for (let c = 0; c < token.length; c += 1) {
        const code = token.charCodeAt(c);
        const isHex =
          (code >= 48 && code <= 57) ||
          (code >= 97 && code <= 102);
        if (!isHex) {
          return null;
        }
      }
      groups.push(Number.parseInt(token, 16));
    }

    return groups;
  };

  if (doubleColonParts.length === 2) {
    const left = parseSegmentList(doubleColonParts[0] ?? "", false);
    const right = parseSegmentList(doubleColonParts[1] ?? "", true);
    if (left === null || right === null || left.length + right.length >= 8) {
      return null;
    }
    const zeroFill = new Array<number>(8 - left.length - right.length).fill(0);
    return [...left, ...zeroFill, ...right];
  }

  const full = parseSegmentList(host, true);
  if (full === null || full.length !== 8) {
    return null;
  }
  return full;
}

/**
 * Extracts embedded 32-bit IPv4 addresses from IPv4-mapped (::ffff:0:0/96),
 * NAT64 (64:ff9b::/96), and IPv4-compatible IPv6 representations.
 */
function extractEmbeddedIpv4FromIpv6(groups: readonly number[]): number | null {
  const g0 = groups[0] ?? 0;
  const g1 = groups[1] ?? 0;
  const g2 = groups[2] ?? 0;
  const g3 = groups[3] ?? 0;
  const g4 = groups[4] ?? 0;
  const g5 = groups[5] ?? 0;
  const g6 = groups[6] ?? 0;
  const g7 = groups[7] ?? 0;

  // ::ffff:w.x.y.z (IPv4-mapped IPv6)
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
    return (((g6 << 16) | g7) >>> 0);
  }

  // 64:ff9b::w.x.y.z (RFC 6052 Well-Known NAT64 prefix)
  if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return (((g6 << 16) | g7) >>> 0);
  }

  // Deprecated IPv4-compatible ::w.x.y.z (excluding :: and ::1)
  if (
    g0 === 0 &&
    g1 === 0 &&
    g2 === 0 &&
    g3 === 0 &&
    g4 === 0 &&
    g5 === 0 &&
    (g6 !== 0 || g7 > 1)
  ) {
    return (((g6 << 16) | g7) >>> 0);
  }

  return null;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replaceAll("_", "").replaceAll("-", "");
}

function looksLikeSchemeUri(value: string): boolean {
  const trimmed = value.trim();
  const lower = trimmed.toLowerCase();

  for (const dangerous of DANGEROUS_SCHEME_PREFIXES) {
    if (lower.startsWith(dangerous)) {
      return true;
    }
  }

  const colonIdx = lower.indexOf("://");
  if (colonIdx <= 0 || colonIdx > 16) {
    return false;
  }

  for (let i = 0; i < colonIdx; i += 1) {
    const code = lower.charCodeAt(i);
    const valid =
      (code >= 97 && code <= 122) ||
      (i > 0 &&
        ((code >= 48 && code <= 57) ||
          code === 43 /* + */ ||
          code === 45 /* - */ ||
          code === 46 /* . */));
    if (!valid) {
      return false;
    }
  }

  return true;
}

/**
 * Bitwise IPv4/IPv6 SSRF guard blocking dangerous URI schemes, private RFC1918 networks,
 * loopback/link-local ranges, and Cloud Instance Metadata Services (AWS/GCP/Azure/Alibaba).
 */
export class SsrfGuard {
  private readonly enabled: boolean;
  private readonly allowedProtocols: ReadonlySet<string>;
  private readonly blockPrivateNetworks: boolean;
  private readonly blockCloudMetadata: boolean;
  private readonly allowedHosts: ReadonlySet<string>;

  public constructor(config: SsrfGuardConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.allowedProtocols = new Set(
      (config.allowedProtocols ?? DEFAULT_ALLOWED_PROTOCOLS).map((p) =>
        p.toLowerCase().endsWith(":") ? p.toLowerCase() : `${p.toLowerCase()}:`
      )
    );
    this.blockPrivateNetworks = config.blockPrivateNetworks ?? true;
    this.blockCloudMetadata = config.blockCloudMetadata ?? true;
    this.allowedHosts = new Set(
      (config.allowedHosts ?? []).map((h) => h.toLowerCase())
    );
  }

  public check(invocation: NormalizedMcpInvocation): GuardCheckResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    if (invocation.operationKind === "resource") {
      const target = invocation.target.trim();
      // Local file:// MCP resources are validated by PathTraversalGuard.
      if (!target.toLowerCase().startsWith("file://") && looksLikeSchemeUri(target)) {
        const resCheck = this.inspectUrlCandidate(target, "uri");
        if (!resCheck.allowed) {
          return resCheck;
        }
      }
    }

    return this.walkArguments(invocation.canonicalArguments, invocation.operationKind);
  }

  private walkArguments(
    node: unknown,
    operationKind: NormalizedMcpInvocation["operationKind"],
    currentKey?: string
  ): GuardCheckResult {
    if (typeof node === "string") {
      const trimmed = node.trim();
      if (trimmed.length === 0) {
        return { allowed: true };
      }

      const normalizedKey =
        currentKey !== undefined ? normalizeKey(currentKey) : "";
      const isExplicitUrlField = EXPLICIT_URL_KEYS.has(normalizedKey);

      if (
        operationKind === "resource" &&
        normalizedKey === "uri" &&
        trimmed.toLowerCase().startsWith("file://")
      ) {
        return { allowed: true };
      }

      if (!isExplicitUrlField && trimmed.toLowerCase().startsWith("file://")) {
        // Non-URL file:// fields (such as 'path' or 'uri' in filesystem tools) belong to PathTraversalGuard.
        return { allowed: true };
      }

      if (isExplicitUrlField || looksLikeSchemeUri(trimmed)) {
        return this.inspectUrlCandidate(trimmed, currentKey ?? "url");
      }

      return { allowed: true };
    }

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        const itemResult = this.walkArguments(node[i], operationKind, currentKey);
        if (!itemResult.allowed) {
          return itemResult;
        }
      }
      return { allowed: true };
    }

    if (typeof node === "object" && node !== null) {
      const record = node as Record<string, unknown>;
      for (const [key, val] of Object.entries(record)) {
        const propResult = this.walkArguments(val, operationKind, key);
        if (!propResult.allowed) {
          return propResult;
        }
      }
    }

    return { allowed: true };
  }

  public inspectUrlCandidate(rawUrl: string, fieldName: string): GuardCheckResult {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return {
        allowed: false,
        reasonCode: "SSRF_BLOCKED",
        detail: `Malformed URL in '${fieldName}' rejected by fail-closed SSRF guard.`
      };
    }

    const protocol = parsed.protocol.toLowerCase();
    if (!this.allowedProtocols.has(protocol)) {
      return {
        allowed: false,
        reasonCode: "SSRF_BLOCKED",
        detail: `Disallowed URL protocol '${protocol}' in '${fieldName}'.`
      };
    }

    if (parsed.username.length > 0 || parsed.password.length > 0) {
      return {
        allowed: false,
        reasonCode: "SSRF_BLOCKED",
        detail: `Embedded URL userinfo credentials in '${fieldName}' are disallowed.`
      };
    }

    const rawHostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (rawHostname.length === 0) {
      return {
        allowed: false,
        reasonCode: "SSRF_BLOCKED",
        detail: `URL in '${fieldName}' is missing a valid hostname.`
      };
    }

    const unbracketedHost =
      rawHostname.startsWith("[") && rawHostname.endsWith("]")
        ? rawHostname.slice(1, -1)
        : rawHostname;

    if (this.allowedHosts.has(rawHostname) || this.allowedHosts.has(unbracketedHost)) {
      return { allowed: true };
    }

    if (this.blockCloudMetadata && CLOUD_METADATA_HOSTNAMES.has(unbracketedHost)) {
      return {
        allowed: false,
        reasonCode: "SSRF_BLOCKED",
        detail: `Cloud metadata hostname '${unbracketedHost}' blocked in '${fieldName}'.`
      };
    }

    if (this.blockPrivateNetworks) {
      if (
        unbracketedHost === "localhost" ||
        unbracketedHost.endsWith(".localhost") ||
        unbracketedHost.endsWith(".local") ||
        unbracketedHost.endsWith(".internal") ||
        unbracketedHost.endsWith(".home.arpa")
      ) {
        return {
          allowed: false,
          reasonCode: "SSRF_BLOCKED",
          detail: `Internal or loopback hostname '${unbracketedHost}' blocked in '${fieldName}'.`
        };
      }
    }

    const ipv4 = parseIpv4(unbracketedHost);
    if (ipv4 !== null) {
      return this.evaluateIpv4Address(ipv4, fieldName);
    }

    const ipv6 = parseIpv6(unbracketedHost);
    if (ipv6 !== null) {
      return this.evaluateIpv6Address(ipv6, fieldName);
    }

    return { allowed: true };
  }

  private evaluateIpv4Address(ipv4: number, fieldName: string): GuardCheckResult {
    if (this.blockCloudMetadata) {
      for (const cidr of CLOUD_METADATA_IPV4_CIDRS) {
        if (isIpv4InCidr(ipv4, cidr)) {
          return {
            allowed: false,
            reasonCode: "SSRF_BLOCKED",
            detail: `Outbound request to ${cidr.label} in '${fieldName}' blocked.`
          };
        }
      }
    }

    if (this.blockPrivateNetworks) {
      for (const cidr of PRIVATE_IPV4_CIDRS) {
        if (isIpv4InCidr(ipv4, cidr)) {
          return {
            allowed: false,
            reasonCode: "SSRF_BLOCKED",
            detail: `Outbound request to private/reserved range (${cidr.label}) in '${fieldName}' blocked.`
          };
        }
      }
    }

    return { allowed: true };
  }

  private evaluateIpv6Address(
    groups: readonly number[],
    fieldName: string
  ): GuardCheckResult {
    // AWS EC2 IPv6 Instance Metadata Service: fd00:ec2::254
    if (
      this.blockCloudMetadata &&
      groups[0] === 0xfd00 &&
      groups[1] === 0x0ec2 &&
      groups[2] === 0 &&
      groups[3] === 0 &&
      groups[4] === 0 &&
      groups[5] === 0 &&
      groups[6] === 0 &&
      groups[7] === 0x0254
    ) {
      return {
        allowed: false,
        reasonCode: "SSRF_BLOCKED",
        detail: `Outbound request to AWS IPv6 IMDS (fd00:ec2::254) in '${fieldName}' blocked.`
      };
    }

    const embeddedIpv4 = extractEmbeddedIpv4FromIpv6(groups);
    if (embeddedIpv4 !== null) {
      return this.evaluateIpv4Address(embeddedIpv4, fieldName);
    }

    if (this.blockPrivateNetworks) {
      const allZeroPrefix =
        groups[0] === 0 &&
        groups[1] === 0 &&
        groups[2] === 0 &&
        groups[3] === 0 &&
        groups[4] === 0 &&
        groups[5] === 0 &&
        groups[6] === 0;

      // ::/128 (Unspecified) and ::1/128 (Loopback)
      if (allZeroPrefix && (groups[7] === 0 || groups[7] === 1)) {
        return {
          allowed: false,
          reasonCode: "SSRF_BLOCKED",
          detail: `IPv6 loopback/unspecified address blocked in '${fieldName}'.`
        };
      }

      const firstGroup = groups[0] ?? 0;

      // fc00::/7 Unique Local Addresses (0xfc00 - 0xfdff)
      if ((firstGroup & 0xfe00) === 0xfc00) {
        return {
          allowed: false,
          reasonCode: "SSRF_BLOCKED",
          detail: `IPv6 Unique Local Address (fc00::/7) blocked in '${fieldName}'.`
        };
      }

      // fe80::/10 Link-Local Unicast (0xfe80 - 0xfebf)
      if ((firstGroup & 0xffc0) === 0xfe80) {
        return {
          allowed: false,
          reasonCode: "SSRF_BLOCKED",
          detail: `IPv6 Link-Local address (fe80::/10) blocked in '${fieldName}'.`
        };
      }

      // ff00::/8 Multicast
      if ((firstGroup & 0xff00) === 0xff00) {
        return {
          allowed: false,
          reasonCode: "SSRF_BLOCKED",
          detail: `IPv6 Multicast address (ff00::/8) blocked in '${fieldName}'.`
        };
      }
    }

    return { allowed: true };
  }
}
