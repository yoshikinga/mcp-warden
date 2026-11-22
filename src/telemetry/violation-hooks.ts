import type {
  ViolationEvent,
  ViolationHook,
  WardenMetricsSnapshot
} from "../types/v1-1.js";

const MAX_DISTINCT_REASON_KEYS = 64;

/**
 * Optional error observer invoked if a user-supplied `ViolationHook` throws or rejects.
 */
export type ViolationHookErrorHandler = (
  error: unknown,
  event: ViolationEvent
) => void;

export interface TelemetryManagerOptions {
  readonly hooks?: readonly ViolationHook[];
  readonly onHookError?: ViolationHookErrorHandler;
}

export interface RecordViolationMetricsParams {
  readonly reasonCode: string;
  readonly blocked: boolean;
  readonly isDryRunWouldDeny: boolean;
  readonly isCircuitBreaker?: boolean;
}

/**
 * Collects bounded operational counters and dispatches real-time `ViolationEvent`
 * notifications with strict fault isolation so failing SIEM/webhook callbacks never crash MCP traffic.
 */
export class TelemetryManager {
  private readonly hooks = new Set<ViolationHook>();
  private readonly onHookError: ViolationHookErrorHandler | null;

  private totalInspected = 0;
  private totalAllowed = 0;
  private totalDenied = 0;
  private totalDryRunWouldDeny = 0;
  private totalEgressScrubbed = 0;
  private totalCircuitBreakerBlocks = 0;
  private readonly reasonsCount = new Map<string, number>();

  public constructor(options: TelemetryManagerOptions = {}) {
    if (options.hooks !== undefined) {
      for (let i = 0; i < options.hooks.length; i += 1) {
        const hook = options.hooks[i];
        if (hook !== undefined) {
          this.hooks.add(hook);
        }
      }
    }
    this.onHookError = options.onHookError ?? null;
  }

  /**
   * Registers a real-time violation listener and returns an unsubscribe function.
   */
  public addHook(hook: ViolationHook): () => void {
    this.hooks.add(hook);
    return (): void => {
      this.hooks.delete(hook);
    };
  }

  /**
   * Records a clean ALLOW decision with zero security violations.
   */
  public recordAllow(): void {
    this.totalInspected += 1;
    this.totalAllowed += 1;
  }

  /**
   * Records an ENFORCE block or DRY_RUN shadow violation.
   */
  public recordViolation(params: RecordViolationMetricsParams): void {
    this.totalInspected += 1;

    if (params.blocked) {
      this.totalDenied += 1;
    } else {
      this.totalAllowed += 1;
    }

    if (params.isDryRunWouldDeny) {
      this.totalDryRunWouldDeny += 1;
    }

    if (params.isCircuitBreaker === true && params.blocked) {
      this.totalCircuitBreakerBlocks += 1;
    }

    this.incrementReasonCounter(params.reasonCode);
  }

  /**
   * Records outbound credential redaction or block events from `EgressSecretGuard`.
   */
  public recordEgressScrubbed(reasonCode: string): void {
    this.totalEgressScrubbed += 1;
    this.incrementReasonCounter(reasonCode);
  }

  /**
   * Dispatches a `ViolationEvent` across all registered hooks inside isolated try/catch blocks.
   */
  public async dispatchViolation(event: ViolationEvent): Promise<void> {
    if (this.hooks.size === 0) {
      return;
    }

    for (const hook of this.hooks) {
      try {
        await hook(event);
      } catch (err: unknown) {
        if (this.onHookError !== null) {
          try {
            this.onHookError(err, event);
          } catch {
            // Suppress secondary observer errors to guarantee non-throwing telemetry.
          }
        }
      }
    }
  }

  /**
   * Returns an immutable point-in-time snapshot of gateway security counters.
   */
  public getSnapshot(): WardenMetricsSnapshot {
    const reasonsObject: Record<string, number> = {};
    for (const [reason, count] of this.reasonsCount.entries()) {
      reasonsObject[reason] = count;
    }

    return {
      totalInspected: this.totalInspected,
      totalAllowed: this.totalAllowed,
      totalDenied: this.totalDenied,
      totalDryRunWouldDeny: this.totalDryRunWouldDeny,
      totalEgressScrubbed: this.totalEgressScrubbed,
      totalCircuitBreakerBlocks: this.totalCircuitBreakerBlocks,
      reasonsCount: reasonsObject
    };
  }

  /**
   * Resets all telemetry counters to zero while preserving registered hooks.
   */
  public resetMetrics(): void {
    this.totalInspected = 0;
    this.totalAllowed = 0;
    this.totalDenied = 0;
    this.totalDryRunWouldDeny = 0;
    this.totalEgressScrubbed = 0;
    this.totalCircuitBreakerBlocks = 0;
    this.reasonsCount.clear();
  }

  private incrementReasonCounter(reasonCode: string): void {
    const current = this.reasonsCount.get(reasonCode);
    if (current !== undefined) {
      this.reasonsCount.set(reasonCode, current + 1);
      return;
    }

    if (this.reasonsCount.size < MAX_DISTINCT_REASON_KEYS) {
      this.reasonsCount.set(reasonCode, 1);
    }
  }
}
