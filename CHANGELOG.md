# Changelog

All notable changes to `mcp-warden` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-23

### Added

- **Full-Duplex Security Kernel (`McpWarden` v1.1):** Extended gateway orchestration with inbound `UnicodeTrojanGuard`, behavioral `SessionCircuitBreaker`, upstream `inspectToolsList()` pinning, and automatic outbound `EgressSecretGuard` scrubbing inside `warden.wrap()`.
- **Trojan Source & Tag Smuggling Guard (`UnicodeTrojanGuard`):** Code-point scanner blocking bidirectional overrides (`U+202A..U+202E`, `U+2066..U+2069`, CVE-2021-42574), invisible zero-width splitters (`U+200B..U+200D`, `U+FEFF`), and Plane 14 ASCII tag smuggling (`U+E0000..U+E007F`).
- **MCP Tool Poisoning & Rug-Pull Shield (`ToolIntegrityGuard`):** Canonical SHA-256 `tools/list` fingerprinting with Trust-On-First-Use (`TOFU`) catalog pinning, static supply-chain hash verification, and covert prompt-directive detection across tool descriptions and JSON schemas.
- **Outbound Credential Scrubber (`EgressSecretGuard`):** ReDoS-free linear span scanners redacting (`[REDACTED_SECRET]`) or blocking leaked AWS keys, GitHub PATs, Anthropic/OpenAI keys, Stripe live keys, Slack tokens, Google API keys, PEM private keys, JWTs, and database URI passwords in tool responses.
- **Behavioral Session Quarantine (`SessionCircuitBreaker`):** Bounded-memory `CLOSED -> OPEN -> HALF_OPEN` state machine isolating probing or hijacked agent sessions in $O(1)$ time with single-flight recovery probes.
- **Secret-Keyed `HMAC-SHA256` Signing & SIEM `NDJSON` (`HmacAuditSigner`, `ndjson-codec.ts`):** Web Crypto `HMAC-SHA256` audit authentication with cached `CryptoKey` instances, zero-downtime key-ring rotation, tail-truncation anchors (`expectedCount`, `expectedLastHash`), and `NdjsonAuditSink`.
- **Enterprise `DRY_RUN` Shadow Mode & Telemetry (`TelemetryManager`):** Live-toggleable `ENFORCE` / `DRY_RUN` modes (`setMode`), fault-isolated `ViolationHook` callbacks (`onViolation`), and real-time operational metrics (`getMetrics`).
- **Zero-Dependency SecOps CLI (`mcp-warden`):** Built-in executable supporting `verify-audit`, `inspect`, and 6-vector cryptographic `self-test`.
- **44-Vector OWASP LLM Red-Team Suite & Architecture Governance:** Added `tests/redteam-owasp-corpus.test.ts`, `THREAT_MODEL.md` (STRIDE + OWASP Top 10 for LLM), ADRs `0001`–`0004`, GitHub CodeQL SAST scanning, RFC 9116 `.github/SECURITY.txt`, and automated `SHA256SUMS.txt` release attestations.

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

[1.1.0]: https://github.com/yoshikinga/mcp-warden/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/yoshikinga/mcp-warden/releases/tag/v1.0.0
