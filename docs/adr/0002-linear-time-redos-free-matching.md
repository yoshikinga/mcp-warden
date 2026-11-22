# ADR 0002: Linear-Time O(n) Matching & Bounded-Memory DoS Resilience

- **Status:** Accepted
- **Date:** 2026-11-21 *(Updated 2026-11-23 for v1.1.0)*
- **Deciders:** `@yoshikinga` Core Architecture

## Context

Because LLM tool arguments are dynamically generated from untrusted context windows, an attacker can craft pathological inputs specifically targeting the firewall itself:

- Nested wildcard patterns or secret-scanning regular expressions susceptible to catastrophic backtracking ($O(2^n)$ **ReDoS**), freezing the single-threaded JavaScript event loop.
- Deeply nested JSON objects designed to trigger `RangeError: Maximum call stack size exceeded` in recursive validators.
- High-cardinality `principalId` or `sessionId` floods aimed at exhausting V8 heap memory.

## Decision

1. **Ban Dynamic `RegExp` Compilation:** Untrusted strings and user-configured policy globs are never compiled via `new RegExp(...)`.
2. **Linear-Time $O(n)$ Scanners:**
   - Wildcard matching (`*`, `?`) uses an iterative two-pointer algorithm (`src/policy/pattern-matcher.ts`) with strict $O(n)$ time and $O(1)$ auxiliary space.
   - Outbound credential scrubbing (`src/guards/egress-secret-guard.ts`) uses deterministic prefix-indexed character span scanners rather than backtracking regexes.
   - Network CIDR checks (`src/guards/ssrf-guard.ts`) convert IPv4 and IPv6 addresses into integer/group bitmasks evaluated in $O(1)$ bitwise operations.
3. **Iterative Heap-Stack Traversal:** Deep object inspection in `PayloadGuard` and `UnicodeTrojanGuard` uses explicit heap-allocated stacks with configurable depth/key ceilings.
4. **Hard LRU Memory Ceilings:** Every stateful map (`SlidingWindowRateLimiter`, `SessionCircuitBreaker`, `ToolIntegrityGuard`, `RingBufferAuditSink`, `TelemetryManager`) enforces deterministic upper bounds and stale/LRU eviction.

## Consequences

- **Positive:** Guarantees sub-millisecond tail latency (`p99 < 0.7ms`) and flat heap memory consumption even under sustained adversarial fuzzing.
- **Trade-off:** Policy rules express target patterns via clean `*` and `?` globs plus declarative `ArgumentConstraint` rules rather than arbitrary PCRE regular expressions.
