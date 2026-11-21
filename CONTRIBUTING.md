# Contributing to `mcp-warden`

Thank you for helping harden Model Context Protocol (MCP) infrastructure. Every contribution is reviewed against strict security, latency, and supply-chain standards so production teams can trust `mcp-warden` inline.

## Core Architectural Invariants

Before opening a Pull Request, make sure your changes preserve all five non-negotiable project invariants:

1. **Zero Production Runtime Dependencies (`0` npm deps):**  
   `package.json` must never contain `dependencies` or `optionalDependencies`. Our CI pipeline automatically fails if any runtime package is added.
2. **Universal Web Standard Portability:**  
   Code inside `src/` must rely exclusively on standard ECMAScript and Web Standard APIs (`globalThis.crypto.subtle`, `TextEncoder`, `TextDecoder`, `URL`, `performance.now`) so builds run identically on Node.js, Bun, Deno, and Cloudflare Workers.
3. **Zero Dynamic RegExp / Linear-Time Matching:**  
   Never compile untrusted patterns or user strings into `new RegExp(...)`. All wildcard, path, and IP checks must maintain predictable linear time and bounded memory.
4. **Fail-Closed & Non-Leaky Client Errors:**  
   Ambiguous or malformed inputs must always deny execution. External JSON-RPC 2.0 error responses (`WardenError.toJsonRpcErrorResponse()`) must never leak internal server directory roots, rule IDs, or credentials back to untrusted LLM clients.
5. **Strict TypeScript Hygiene:**  
   All source and test files must pass `strict: true`, `noUncheckedIndexedAccess: true`, `noImplicitOverride: true`, and zero `any` types.

## Local Development Workflow

### Prerequisites

- **Node.js `>= 20.0.0`** (Node.js 22 LTS recommended)
- `npm` `>= 10`

### Setup & Verification Commands

```bash
# 1. Install dev-only TypeScript & ESLint toolchain
npm install

# 2. Run static lint checks
npm run lint

# 3. Run strict TypeScript compiler checks
npm run typecheck

# 4. Build ESM output and .d.ts declarations into dist/
npm run build

# 5. Run native node:test unit & integration suite
npm test

# 6. Measure p50/p99 inline pipeline latency & memory bounds
npm run bench
```

## Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/) to power automated semantic versioning and Release Drafter notes:

- `feat(guards): ...` — New security guard capability or policy feature
- `fix(ssrf): ...` — Bug or edge-case bypass fix
- `perf(policy): ...` — Latency or memory optimization
- `test(audit): ...` — New or expanded unit/integration test cases
- `docs(readme): ...` — Documentation or runnable examples
- `ci(actions): ...` / `chore(...): ...` — Tooling and repository maintenance

## Submitting a Pull Request

1. Fork the repository and create a topic branch from `main`.
2. Add comprehensive tests in `tests/*.test.ts` covering both valid allow-paths and adversarial attack payloads.
3. Verify `npm run prepublishOnly` completes with zero errors.
4. Open a Pull Request completing every item in `.github/PULL_REQUEST_TEMPLATE.md`.
