import type { RateLimitConfig } from "../types/policy.js";
import type { GuardCheckResult } from "./payload-guard.js";

const DEFAULT_WINDOW_MS = 60_000;
const DEFAULT_MAX_REQUESTS = 60;
const DEFAULT_MAX_TRACKED_KEYS = 10_000;

/**
 * Linear-time O(n) wildcard glob matcher ('*' and '?') used for per-target rate overrides
 * without compiling untrusted patterns into RegExp.
 */
function matchesTargetGlob(pattern: string, target: string): boolean {
  let pIdx = 0;
  let tIdx = 0;
  let starIdx = -1;
  let matchIdx = 0;

  while (tIdx < target.length) {
    if (
      pIdx < pattern.length &&
      (pattern.charCodeAt(pIdx) === 63 /* '?' */ ||
        pattern.charCodeAt(pIdx) === target.charCodeAt(tIdx))
    ) {
      pIdx += 1;
      tIdx += 1;
    } else if (pIdx < pattern.length && pattern.charCodeAt(pIdx) === 42 /* '*' */) {
      starIdx = pIdx;
      matchIdx = tIdx;
      pIdx += 1;
    } else if (starIdx !== -1) {
      pIdx = starIdx + 1;
      matchIdx += 1;
      tIdx = matchIdx;
    } else {
      return false;
    }
  }

  while (pIdx < pattern.length && pattern.charCodeAt(pIdx) === 42 /* '*' */) {
    pIdx += 1;
  }

  return pIdx === pattern.length;
}

/**
 * Bounded-memory Sliding Window Rate Limiter tracking invocations per (principalId, target)
 * with deterministic stale/LRU bucket eviction.
 */
export class SlidingWindowRateLimiter {
  private readonly enabled: boolean;
  private readonly windowMs: number;
  private readonly maxRequestsPerWindow: number;
  private readonly maxTrackedKeys: number;
  private readonly targetOverrides: ReadonlyArray<readonly [string, number]>;
  private readonly nowFn: () => number;
  private readonly buckets = new Map<string, number[]>();

  public constructor(
    config: RateLimitConfig = {},
    nowFn: () => number = () => Date.now()
  ) {
    this.enabled = config.enabled ?? true;
    this.windowMs = Math.max(1, config.windowMs ?? DEFAULT_WINDOW_MS);
    this.maxRequestsPerWindow = Math.max(
      1,
      config.maxRequestsPerWindow ?? DEFAULT_MAX_REQUESTS
    );
    this.maxTrackedKeys = Math.max(
      1,
      config.maxTrackedKeys ?? DEFAULT_MAX_TRACKED_KEYS
    );
    this.targetOverrides = Object.entries(config.targetOverrides ?? {});
    this.nowFn = nowFn;
  }

  /**
   * Records and evaluates an invocation for `(principalId, target)`.
   */
  public check(principalId: string, target: string): GuardCheckResult {
    if (!this.enabled) {
      return { allowed: true };
    }

    const now = this.nowFn();
    const cutoff = now - this.windowMs;
    const limit = this.resolveQuotaForTarget(target);
    const compositeKey = `${principalId}\u001f${target}`;

    let timestamps = this.buckets.get(compositeKey);
    if (timestamps !== undefined) {
      // Refresh Map insertion order for LRU tracking and prune expired entries.
      this.buckets.delete(compositeKey);
      let firstValidIdx = 0;
      while (
        firstValidIdx < timestamps.length &&
        (timestamps[firstValidIdx] ?? 0) <= cutoff
      ) {
        firstValidIdx += 1;
      }
      if (firstValidIdx > 0) {
        timestamps = timestamps.slice(firstValidIdx);
      }
    } else {
      if (this.buckets.size >= this.maxTrackedKeys) {
        this.evictExpiredOrOldest(cutoff);
      }
      timestamps = [];
    }

    if (timestamps.length >= limit) {
      this.buckets.set(compositeKey, timestamps);
      return {
        allowed: false,
        reasonCode: "RATE_LIMIT_EXCEEDED",
        detail: `Principal '${principalId}' exceeded rate limit (${limit} requests / ${this.windowMs}ms) on target '${target}'.`
      };
    }

    timestamps.push(now);
    this.buckets.set(compositeKey, timestamps);
    return { allowed: true };
  }

  /**
   * Returns current number of tracked `(principalId, target)` keys in memory.
   */
  public getTrackedKeyCount(): number {
    return this.buckets.size;
  }

  /**
   * Clears all rate-limit counters.
   */
  public reset(): void {
    this.buckets.clear();
  }

  private resolveQuotaForTarget(target: string): number {
    let matchedQuota: number | null = null;

    for (let i = 0; i < this.targetOverrides.length; i += 1) {
      const entry = this.targetOverrides[i];
      if (entry === undefined) {
        continue;
      }
      const [pattern, quota] = entry;
      if (matchesTargetGlob(pattern, target)) {
        const safeQuota = Math.max(0, quota);
        // Apply strictest matching override when multiple patterns match.
        if (matchedQuota === null || safeQuota < matchedQuota) {
          matchedQuota = safeQuota;
        }
      }
    }

    return matchedQuota ?? this.maxRequestsPerWindow;
  }

  private evictExpiredOrOldest(cutoff: number): void {
    for (const [key, timestamps] of this.buckets.entries()) {
      const newest = timestamps[timestamps.length - 1];
      if (newest === undefined || newest <= cutoff) {
        this.buckets.delete(key);
      }
    }

    while (this.buckets.size >= this.maxTrackedKeys) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.buckets.delete(oldestKey);
    }
  }
}
