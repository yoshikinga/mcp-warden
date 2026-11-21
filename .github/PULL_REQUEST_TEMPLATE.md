## Summary

<!-- Briefly describe the problem solved or security capability introduced, and reference any related Issue (#). -->

## Architectural & Security Checklist

Please verify every invariant below before requesting review:

- [ ] **Zero Runtime Dependencies:** `package.json` introduces `0` production `dependencies` or `optionalDependencies`.
- [ ] **Universal Runtime Compatibility:** Uses pure TypeScript and standard Web APIs (`crypto.subtle`, `TextEncoder`, `URL`) without Node-only runtime globals inside `src/`.
- [ ] **ReDoS & DoS Safety:** No dynamic `new RegExp()` on untrusted input; loops and in-memory maps enforce deterministic bounds.
- [ ] **Fail-Closed Semantics & Non-Leaky Errors:** Ambiguous inputs fail closed, and external JSON-RPC error messages never expose internal server paths or secrets.
- [ ] **Strict Typing & Tests:** Added unit/integration tests in `tests/*.test.ts` covering both allow paths and adversarial bypass vectors.

## Verification

- [ ] `npm run lint` passes with 0 warnings/errors
- [ ] `npm run typecheck` passes under strict TypeScript settings
- [ ] `npm run build` emits clean ESM output and `.d.ts` declarations
- [ ] `npm test` passes 100%
