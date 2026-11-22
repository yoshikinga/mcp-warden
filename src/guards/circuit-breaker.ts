import type {
  CircuitBreakerCheckResult,
  CircuitBreakerConfig,
  CircuitBreakerSnapshot,
  CircuitBreakerState
} from "../types/v1-1.js";

const DEFAULT_FAILURE_THRESHOLD = 5;
const DEFAULT_FAILURE_WINDOW_MS = 30_000;
const DEFAULT_COOLDOWN_MS = 60_000;
const DEFAULT_MAX_TRACKED_SESSIONS = 10_000;

interface SessionBucket {
  state: CircuitBreakerState;
  violations: number[];
  openedAtMs: number | null;
  probeInFlight: boolean;
  lastUpdatedAtMs: number;
}

/**
 * Bounded-memory behavioral Session Circuit Breaker (`CLOSED` -> `OPEN` -> `HALF_OPEN`)
 * that automatically quarantines principals or sessions exhibiting repeated security violations.
 */
export class SessionCircuitBreaker {
  private readonly enabled: boolean;
  private readonly failureThreshold: number;
  private readonly failureWindowMs: number;
  private readonly cooldownMs: number;
  private readonly maxTrackedSessions: number;
  private readonly nowFn: () => number;
  private readonly sessions = new Map<string, SessionBucket>();

  public constructor(
    config: CircuitBreakerConfig = {},
    nowFn: () => number = () => Date.now()
  ) {
    this.enabled = config.enabled ?? true;
    this.failureThreshold = Math.max(
      1,
      config.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD
    );
    this.failureWindowMs = Math.max(
      1,
      config.failureWindowMs ?? DEFAULT_FAILURE_WINDOW_MS
    );
    this.cooldownMs = Math.max(1, config.cooldownMs ?? DEFAULT_COOLDOWN_MS);
    this.maxTrackedSessions = Math.max(
      1,
      config.maxTrackedSessions ?? DEFAULT_MAX_TRACKED_SESSIONS
    );
    this.nowFn = nowFn;
  }

  /**
   * Evaluates in O(1) time whether the session/principal key is permitted to proceed.
   */
  public checkBeforeRequest(key: string): CircuitBreakerCheckResult {
    if (!this.enabled) {
      return { allowed: true, state: "CLOSED" };
    }

    const bucket = this.sessions.get(key);
    if (bucket === undefined) {
      return { allowed: true, state: "CLOSED" };
    }

    const now = this.nowFn();
    this.touchBucket(key, bucket, now);

    if (bucket.state === "OPEN") {
      const openedAt = bucket.openedAtMs ?? now;
      const elapsed = now - openedAt;
      if (elapsed < this.cooldownMs) {
        const remainingCooldownMs = this.cooldownMs - elapsed;
        return {
          allowed: false,
          state: "OPEN",
          reasonCode: "CIRCUIT_BREAKER_OPEN",
          remainingCooldownMs,
          detail: `Session '${key}' is quarantined by circuit breaker (${remainingCooldownMs}ms cooldown remaining).`
        };
      }

      // Cooldown elapsed: transition to HALF_OPEN and permit exactly one trial probe
      bucket.state = "HALF_OPEN";
      bucket.probeInFlight = true;
      return { allowed: true, state: "HALF_OPEN" };
    }

    if (bucket.state === "HALF_OPEN") {
      if (bucket.probeInFlight) {
        return {
          allowed: false,
          state: "HALF_OPEN",
          reasonCode: "CIRCUIT_BREAKER_OPEN",
          remainingCooldownMs: this.cooldownMs,
          detail: `Session '${key}' is in HALF_OPEN recovery with a verification probe already in flight.`
        };
      }
      bucket.probeInFlight = true;
      return { allowed: true, state: "HALF_OPEN" };
    }

    return { allowed: true, state: "CLOSED" };
  }

  /**
   * Feeds the pipeline enforcement result (`allowed: true | false`) back into the state machine.
   */
  public recordOutcome(key: string, allowed: boolean): CircuitBreakerState {
    if (!this.enabled) {
      return "CLOSED";
    }

    const now = this.nowFn();
    let bucket = this.sessions.get(key);

    if (allowed) {
      if (bucket !== undefined) {
        if (bucket.state === "HALF_OPEN") {
          bucket.state = "CLOSED";
          bucket.violations = [];
          bucket.openedAtMs = null;
          bucket.probeInFlight = false;
        }
        this.touchBucket(key, bucket, now);
      }
      return bucket?.state ?? "CLOSED";
    }

    if (bucket === undefined) {
      if (this.sessions.size >= this.maxTrackedSessions) {
        this.evictStaleOrOldest(now);
      }
      bucket = {
        state: "CLOSED",
        violations: [],
        openedAtMs: null,
        probeInFlight: false,
        lastUpdatedAtMs: now
      };
    }

    if (bucket.state === "HALF_OPEN") {
      bucket.state = "OPEN";
      bucket.openedAtMs = now;
      bucket.probeInFlight = false;
      this.touchBucket(key, bucket, now);
      return "OPEN";
    }

    const windowCutoff = now - this.failureWindowMs;
    bucket.violations = bucket.violations.filter((ts) => ts > windowCutoff);
    bucket.violations.push(now);

    if (bucket.violations.length >= this.failureThreshold) {
      bucket.state = "OPEN";
      bucket.openedAtMs = now;
      bucket.probeInFlight = false;
    }

    this.touchBucket(key, bucket, now);
    return bucket.state;
  }

  /**
   * Returns a read-only diagnostic snapshot for a session/principal key.
   */
  public getSnapshot(key: string): CircuitBreakerSnapshot {
    const now = this.nowFn();
    const bucket = this.sessions.get(key);

    if (bucket === undefined) {
      return {
        key,
        state: "CLOSED",
        recentViolations: 0,
        openedAtMs: null,
        remainingCooldownMs: 0
      };
    }

    const windowCutoff = now - this.failureWindowMs;
    const recentViolations = bucket.violations.filter(
      (ts) => ts > windowCutoff
    ).length;

    let remainingCooldownMs = 0;
    if (bucket.state === "OPEN" && bucket.openedAtMs !== null) {
      remainingCooldownMs = Math.max(
        0,
        this.cooldownMs - (now - bucket.openedAtMs)
      );
    }

    return {
      key,
      state: bucket.state,
      recentViolations,
      openedAtMs: bucket.openedAtMs,
      remainingCooldownMs
    };
  }

  public getTrackedSessionCount(): number {
    return this.sessions.size;
  }

  public resetKey(key: string): void {
    this.sessions.delete(key);
  }

  public resetAll(): void {
    this.sessions.clear();
  }

  private touchBucket(key: string, bucket: SessionBucket, now: number): void {
    bucket.lastUpdatedAtMs = now;
    this.sessions.delete(key);
    this.sessions.set(key, bucket);
  }

  private evictStaleOrOldest(now: number): void {
    const staleThreshold = Math.max(this.failureWindowMs, this.cooldownMs);

    for (const [existingKey, existingBucket] of this.sessions.entries()) {
      if (
        existingBucket.state === "CLOSED" &&
        now - existingBucket.lastUpdatedAtMs > staleThreshold
      ) {
        this.sessions.delete(existingKey);
      }
    }

    while (this.sessions.size >= this.maxTrackedSessions) {
      const oldestKey = this.sessions.keys().next().value;
      if (oldestKey === undefined) {
        break;
      }
      this.sessions.delete(oldestKey);
    }
  }
}
