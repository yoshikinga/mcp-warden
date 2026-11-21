# Security Policy

`mcp-warden` sits inline as a security enforcement boundary between untrusted LLM/Agent outputs and critical Model Context Protocol (MCP) infrastructure. We treat every bypass or integrity flaw with the highest priority.

## Supported Versions

| Version | Supported | Runtime Baseline |
| :--- | :--- | :--- |
| `1.0.x` | Yes | Node.js `>= 20`, Bun, Deno, Cloudflare Workers |
| `< 1.0.0` | No | Pre-release snapshots |

## In-Scope Security Vulnerabilities

Please report any reproducible issue in the following categories privately:

1. **Canonicalization Evasion:** Multi-encoding, Unicode normalization, or control-character sequences that bypass downstream inspection while reaching the underlying MCP handler.
2. **Filesystem Root-Jail Escape:** Lexical path inputs that resolve outside `allowedRoots` or bypass the built-in sensitive dotfile denylist.
3. **SSRF Filter Bypass:** URLs or IP representations (IPv4, IPv6, NAT64, IPv4-mapped IPv6, or cloud metadata endpoints) that bypass `SsrfGuard` when `blockPrivateNetworks` or `blockCloudMetadata` is enabled.
4. **Command Injection Evasion:** Shell metacharacter, subshell, or multiline payloads that bypass `CommandInjectionGuard` in strict command contexts.
5. **RBAC Precedence Violation:** Scenarios where an `ALLOW` rule overrides an applicable `DENY` rule, or where unmatched operations fail open.
6. **Audit Chain Forgery:** Inputs enabling undetected mutation, deletion, or reordering of entries verified by `verifyAuditChain()`.
7. **Algorithmic Complexity / DoS:** Inputs causing super-linear CPU stalls (ReDoS), call-stack overflows, or unbounded memory growth bypassing `PayloadGuard` and `SlidingWindowRateLimiter` ceilings.

## Out of Scope

- Semantic or intent-level prompt manipulation where the AI Agent invokes an **explicitly allowed** tool with **schema-valid, non-malicious arguments** inside its configured rate quota. (`mcp-warden` is a deterministic protocol and policy firewall, not a probabilistic LLM intent classifier).

## Reporting a Vulnerability Privately

**Please do NOT report security bypasses through public GitHub Issues, Discussions, or Pull Requests.**

Use either of our private disclosure channels:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Submit a confidential report at [`https://github.com/yoshikinga/mcp-warden/security/advisories/new`](https://github.com/yoshikinga/mcp-warden/security/advisories/new).
2. **Direct Maintainer Email:**  
   Send an email to **`yuki0528@dd.iij4u.or.jp`** with the subject line `[SECURITY] mcp-warden: <short summary>`.

Include a minimal `WardenConfig`, the exact JSON-RPC 2.0 request payload, your runtime version, and the unexpected inspection outcome.

## Coordinated Disclosure & Response Targets

| Milestone | Target SLA |
| :--- | :--- |
| Initial acknowledgement | `< 24 hours` |
| Triage & severity confirmation | `< 72 hours` |
| Patch release & regression test | `< 7 days` (Critical/High) |
| Public GitHub Security Advisory (GHSA) & reporter credit | Upon patch release |
