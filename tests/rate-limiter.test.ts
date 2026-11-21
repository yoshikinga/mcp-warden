import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SlidingWindowRateLimiter } from "../src/index.js";

describe("SlidingWindowRateLimiter", () => {
  it("enforces per-principal sliding windows and recovers smoothly over time", () => {
    let nowMs = 1_000_000;
    const limiter = new SlidingWindowRateLimiter(
      {
        windowMs: 10_000,
        maxRequestsPerWindow: 3
      },
      () => nowMs
    );

    assert.equal(limiter.check("agent-a", "fs:read").allowed, true);
    nowMs += 2_000;
    assert.equal(limiter.check("agent-a", "fs:read").allowed, true);
    nowMs += 2_000;
    assert.equal(limiter.check("agent-a", "fs:read").allowed, true);

    // 4th call within 10s window is throttled for agent-a
    const throttled = limiter.check("agent-a", "fs:read");
    assert.equal(throttled.allowed, false);
    if (!throttled.allowed) {
      assert.equal(throttled.reasonCode, "RATE_LIMIT_EXCEEDED");
    }

    // Distinct principal remains unaffected
    assert.equal(limiter.check("agent-b", "fs:read").allowed, true);

    // Advance past first timestamp (1_000_000 + 10_001 = 1_010_001)
    nowMs = 1_010_001;
    assert.equal(limiter.check("agent-a", "fs:read").allowed, true);
  });

  it("applies strictest matching wildcard targetOverrides", () => {
    const nowMs = 500_000;
    const limiter = new SlidingWindowRateLimiter(
      {
        windowMs: 60_000,
        maxRequestsPerWindow: 50,
        targetOverrides: {
          "db:*": 5,
          "db:delete_*": 1
        }
      },
      () => nowMs
    );

    assert.equal(limiter.check("agent-1", "db:delete_row").allowed, true);
    assert.equal(limiter.check("agent-1", "db:delete_row").allowed, false);
  });

  it("bounds memory strictly within maxTrackedKeys via stale and LRU eviction", () => {
    let nowMs = 10_000;
    const limiter = new SlidingWindowRateLimiter(
      {
        windowMs: 5_000,
        maxRequestsPerWindow: 2,
        maxTrackedKeys: 3
      },
      () => nowMs
    );

    limiter.check("p1", "tool:a");
    nowMs += 100;
    limiter.check("p2", "tool:a");
    nowMs += 100;
    limiter.check("p3", "tool:a");
    assert.equal(limiter.getTrackedKeyCount(), 3);

    // Adding 4th active key evicts oldest LRU key (p1) while preserving hard ceiling
    nowMs += 100;
    limiter.check("p4", "tool:a");
    assert.equal(limiter.getTrackedKeyCount(), 3);
  });
});
