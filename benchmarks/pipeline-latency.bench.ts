import {
  McpWarden,
  createStrictProductionPreset,
  type ExecutionContext
} from "../src/index.js";

function computePercentile(sortedValues: readonly number[], p: number): number {
  if (sortedValues.length === 0) {
    return 0;
  }
  const index = Math.min(
    sortedValues.length - 1,
    Math.max(0, Math.ceil((p / 100) * sortedValues.length) - 1)
  );
  return sortedValues[index] ?? 0;
}

async function runBenchmark(): Promise<void> {
  const iterations = 5_000;
  const warmupIterations = 500;

  const warden = new McpWarden(
    createStrictProductionPreset({
      allowedRoots: ["/srv/workspace"],
      maxRequestsPerWindow: 1_000_000,
      rules: [
        {
          id: "bench-allow-tools",
          effect: "ALLOW",
          roles: ["agent"],
          operations: ["tool"],
          targets: ["fs:read_file", "web:fetch"],
          argumentConstraints: {
            limit: { type: "number", min: 1, max: 500 }
          }
        }
      ]
    }),
    { maxMemoryAuditEntries: 1_000 }
  );

  const context: ExecutionContext = {
    principalId: "bench-agent-01",
    roles: ["agent"],
    sessionId: "bench-session"
  };

  const workloads: readonly unknown[] = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/workspace/docs/architecture.md", limit: 100 }
      }
    },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/workspace/..%252f..%252f.env", apiKey: "sk-secret" }
      }
    },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "web:fetch",
        arguments: { url: "http://[::ffff:169.254.169.254]/latest/meta-data/" }
      }
    },
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "admin:drop_database",
        arguments: { confirm: true }
      }
    }
  ];

  // Warm up JIT and Web Crypto subtle pipeline
  for (let i = 0; i < warmupIterations; i += 1) {
    await warden.inspect(workloads[i % workloads.length], context);
  }

  const heapBefore = process.memoryUsage().heapUsed;
  const latenciesMs: number[] = [];
  const suiteStart = performance.now();

  for (let i = 0; i < iterations; i += 1) {
    const payload = workloads[i % workloads.length];
    const t0 = performance.now();
    await warden.inspect(payload, context);
    latenciesMs.push(performance.now() - t0);
  }

  const totalElapsedMs = performance.now() - suiteStart;
  const heapAfter = process.memoryUsage().heapUsed;

  latenciesMs.sort((a, b) => a - b);

  const p50 = computePercentile(latenciesMs, 50);
  const p95 = computePercentile(latenciesMs, 95);
  const p99 = computePercentile(latenciesMs, 99);
  const mean =
    latenciesMs.reduce((acc, val) => acc + val, 0) / latenciesMs.length;
  const throughput = Math.round((iterations / totalElapsedMs) * 1_000);
  const heapDeltaKiB = Math.round((heapAfter - heapBefore) / 1024);

  const auditReport = await warden.verifyAuditTrail();

  console.log("=== mcp-warden v1.0.0 Inline Pipeline Benchmark ===");
  console.log(`Runtime          : Node.js ${process.version} (${process.platform}/${process.arch})`);
  console.log(`Iterations       : ${iterations.toLocaleString()} mixed MCP tool calls (SHA-256 audit enabled)`);
  console.log(`Latency p50      : ${p50.toFixed(3)} ms`);
  console.log(`Latency mean     : ${mean.toFixed(3)} ms`);
  console.log(`Latency p95      : ${p95.toFixed(3)} ms`);
  console.log(`Latency p99      : ${p99.toFixed(3)} ms`);
  console.log(`Throughput       : ${throughput.toLocaleString()} inspections/sec`);
  console.log(`Bounded Heap Δ   : ${heapDeltaKiB} KiB`);
  console.log(`Audit Chain Valid: ${auditReport.valid} (${auditReport.checkedCount} retained ring entries)`);
}

void runBenchmark();
