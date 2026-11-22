# ADR 0001: Zero Production Runtime Dependencies & Web Standard Portability

- **Status:** Accepted
- **Date:** 2026-11-21 *(Updated 2026-11-23 for v1.1.0)*
- **Deciders:** `@yoshikinga` Core Architecture

## Context

`mcp-warden` executes inline inside the security-critical path of Model Context Protocol (MCP) gateways and AI Agent hosts. Traditional JavaScript/TypeScript middleware packages pull in dozens of transitive `npm` packages for schema validation, glob matching, IP CIDR parsing, and cryptographic hashing.

In a security boundary component, third-party runtime dependencies create three unacceptable risks:

1. **Supply-Chain Attack Surface:** Compromised maintainer accounts, malicious patch releases, or typosquatted transitive packages execute with full host privileges.
2. **Compliance & CVE Churn:** Enterprise SOC2/ISO27001 teams face continuous vulnerability triage noise from transitive dependencies unrelated to core functionality.
3. **Runtime Lock-In:** Packages relying on Node-specific C++ addons or `node:crypto` / `node:path` internals fail inside Cloudflare Workers, Deno, or Bun edge gateways.

## Decision

1. **Strict Zero-Dependency Invariant:** `package.json` MUST maintain `0` `dependencies`, `0` `optionalDependencies`, and `0` `peerDependencies`. This rule is enforced automatically on every push and pull request in `.github/workflows/ci.yml`.
2. **Web Standard Runtime Baseline:** Core modules inside `src/` (excluding the optional Node CLI wrapper `src/cli/bin.ts`) rely exclusively on standard ECMAScript and Web Standard APIs (`globalThis.crypto.subtle`, `TextEncoder`, `TextDecoder`, `URL`, `performance.now`).

## Consequences

- **Positive:** Permanently eliminates transitive runtime supply-chain CVEs, guarantees sub-millisecond cold starts, enables frictionless enterprise security audits, and runs identically across Node.js `>= 20`, Bun, Deno, and Cloudflare Workers.
- **Trade-off:** Core algorithms (RFC 8785 canonical JSON, iterative glob matching, bitwise IPv4/IPv6 CIDR masks, and NDJSON schema validation) are maintained in-house with exhaustive unit and red-team test suites.
