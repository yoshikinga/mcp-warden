# Security Policy

`mcp-warden` operates inline as a full-duplex security enforcement boundary between untrusted LLM/Agent outputs and critical Model Context Protocol (MCP) infrastructure. We treat every guard bypass or cryptographic integrity flaw with the highest priority.

For architectural trust boundaries, STRIDE analysis, and OWASP LLM Top 10 mappings, review [`THREAT_MODEL.md`](./THREAT_MODEL.md). Machine-readable RFC 9116 disclosure metadata is published at [`.github/SECURITY.txt`](./.github/SECURITY.txt).

## Supported Versions

| Version | Supported | Security Capabilities |
| :--- | :--- | :--- |
| `1.1.x` | Yes (Recommended) | Full-Duplex Ingress/Egress Kernel, Rug-Pull Pinning, Unicode Trojan Guard, `HMAC-SHA256` Audit & CLI |
| `1.0.x` | Critical Fixes Only | 6-Stage Ingress Firewall, Zero-Trust RBAC & Unkeyed `SHA-256` Audit |
| `< 1.0.0` | No | Pre-release snapshots |

## In-Scope Security Vulnerabilities

Please report any reproducible issue in the following categories privately:

1. **Canonicalization & Unicode Trojan Evasion:** Multi-encoding, overlong UTF-8, null-byte, bidirectional override (`U+202A..U+202E`, `U+2066..U+2069`), zero-width character, or Plane 14 tag sequences (`U+E0000..U+E007F`) that evade `canonicalizer.ts` or `UnicodeTrojanGuard`.
2. **Filesystem Root-Jail Escape:** Lexical path inputs that resolve outside `allowedRoots`, collide with sibling prefixes, or bypass the sensitive credential file denylist.
3. **SSRF Filter Bypass:** URLs or IP representations (IPv4, IPv6, NAT64 `64:ff9b::/96`, IPv4-mapped IPv6 `[::ffff:a9fe:a9fe]`, or cloud metadata endpoints) that bypass `SsrfGuard`.
4. **Command Injection Evasion:** Shell metacharacter, subshell, pipe, or multiline payloads that bypass `CommandInjectionGuard` in command contexts.
5. **MCP Tool Poisoning & Rug-Pull Pinning Bypass:** Upstream `tools/list` schema or description mutations that evade `ToolIntegrityGuard` SHA-256 fingerprint pinning.
6. **Outbound Egress Secret Bypass:** Supported credential formats (AWS `AKIA*`, GitHub PATs, Anthropic/OpenAI/Stripe/Slack/Google keys, PEM private keys, JWTs, or DB URI passwords) leaking past `EgressSecretGuard` when enabled.
7. **RBAC Precedence or Circuit-Breaker Bypass:** Scenarios where an `ALLOW` rule overrides an applicable `DENY` rule, unmatched operations fail open, or `OPEN` sessions bypass `SessionCircuitBreaker` in `ENFORCE` mode.
8. **Audit Chain or HMAC-SHA256 Forgery:** Undetected mutation, deletion, reordering, or signature forgery accepted by `verifyAuditChain()`, `verifySignedAuditChain()`, or `mcp-warden verify-audit`.
9. **Algorithmic Complexity / DoS:** Inputs causing super-linear CPU stalls (ReDoS), call-stack overflows, or unbounded memory growth bypassing configured guard ceilings.

## Out of Scope

- Semantic business-logic misuse where an AI Agent invokes an **explicitly allowed** tool with **schema-valid, non-malicious arguments** inside its configured rate quota.
- Dynamic DNS rebinding on external hostnames where IP resolution occurs inside a downstream HTTP client outside `mcp-warden` (see [`THREAT_MODEL.md`](./THREAT_MODEL.md)).

## Reporting a Vulnerability Privately

**Please do NOT report security bypasses through public GitHub Issues, Discussions, or Pull Requests.**

Use either private disclosure channel:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Submit a confidential report at [`https://github.com/yoshikinga/mcp-warden/security/advisories/new`](https://github.com/yoshikinga/mcp-warden/security/advisories/new).
2. **Direct Maintainer Email:**  
   Send an email to **`yuki0528@dd.iij4u.or.jp`** with the subject line `[SECURITY] mcp-warden: <short summary>`.

Include a minimal `WardenV11Config`, the exact JSON-RPC 2.0 request/response payload, your runtime version, and the unexpected inspection outcome.

## Coordinated Disclosure & Response Targets

| Milestone | Target SLA |
| :--- | :--- |
| Initial acknowledgement | `< 24 hours` |
| Triage & severity confirmation | `< 72 hours` |
| Patch release & regression test | `< 7 days` (Critical/High) |
| Public GitHub Security Advisory (GHSA) & reporter credit | Upon patch release |
