# Changelog

All notable changes to `mcp-warden` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-21

### Added

- **Core Gateway (`McpWarden`):** 6-stage inline inspection pipeline (`inspect`, `assertAllowed`, `wrap`) protecting MCP `tools/call`, `resources/read`, `prompts/get`, and lifecycle operations with sanitized JSON-RPC 2.0 client error mapping (`-32600` to `-32004`).
- **Multi-Pass Canonicalizer (`canonicalizer.ts`):** Iterative RFC 3986 percent-decoding with fatal UTF-8 validation, Unicode `NFC` normalization, and immediate null-byte (`\u0000`) / control-character rejection without mutating raw downstream payloads.
- **DoS & Structural Shield (`PayloadGuard`):** Deterministic UTF-8 byte budget (default `64 KiB`), iterative heap-stack JSON depth limit, total object key ceiling, max string length check, and JSON-RPC batch array rejection.
- **Filesystem Root-Jail (`PathTraversalGuard`):** Lexical path containment within `allowedRoots`, `../` escape prevention, and built-in denylists for `.env*`, `.ssh/*`, `.aws/*`, `.git/config`, `/etc/passwd`, and private key extensions.
- **Shell Execution Shield (`CommandInjectionGuard`):** Detection of subshells (`$()`, `` ` ``), parameter expansion (`${}`), command chaining (`;`, `&&`, `||`), pipes (`|`), redirections, and multiline command injections.
- **Bitwise Network Filter (`SsrfGuard`):** Scheme allowlisting plus bitwise IPv4/IPv6 CIDR filtering blocking `localhost`, RFC1918 private ranges, link-local addresses, AWS/GCP/Azure/Alibaba Cloud Metadata IPs (`169.254.169.254`, `fd00:ec2::254`), and hex-normalized IPv4-mapped IPv6 bypasses (`[::ffff:a9fe:a9fe]`).
- **Bounded Rate Limiter (`SlidingWindowRateLimiter`):** Per-`(principalId, target)` sliding-window quotas with $O(n)$ glob overrides and stale/LRU key eviction capped at `maxTrackedKeys`.
- **Zero-Trust RBAC Engine (`PolicyEngine`):** Explicit `DENY` over `ALLOW` precedence, fail-closed defaults, linear-time $O(n)$ glob matching (zero ReDoS), and typed `ArgumentConstraint` validation (`required`, `type`, `enum`, `min`, `max`, `maxLength`, `allowedPrefixes`).
- **Tamper-Evident Audit Trail (`AuditLogger` & `verifyAuditChain`):** Concurrency-safe sequential SHA-256 hash chaining powered by Web Crypto (`crypto.subtle`) over RFC 8785 key-sorted JSON, automatic credential field scrubbing, and `RingBufferAuditSink`.
- **Turnkey Security Presets:** `createStrictProductionPreset()` and `createReadOnlyAgentPreset()` for rapid server hardening.

[1.0.0]: https://github.com/yoshikinga/mcp-warden/releases/tag/v1.0.0
