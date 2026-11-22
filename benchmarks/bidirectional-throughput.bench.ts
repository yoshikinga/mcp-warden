import {
  JSONRPC_VERSION,
  McpWarden,
  createStrictProductionPreset,
  verifyAuditNdjson,
  type ExecutionContext,
  type JsonRpcSuccessResponse,
  type NormalizedMcpInvocation
} from "../src/index.js";

function percentile(sorted: readonly number[], targetP: number): number {
  if (sorted.length === 0) {
    return 0;
  }
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((targetP / 100) * sorted.length) - 1)
  );
  return sorted[idx] ?? 0;
}

async function runFullDuplexBenchmark(): Promise<void> {
  const iterations = 4_000;
  const warmupIterations = 400;
  const hmacSecret = "bench-v1-1-full-duplex-hmac-secret-2026";
  const synthAwsKey = ["AK", "IA", "IOSFODNN7EXAMPLE"].join("");

  const basePreset = createStrictProductionPreset({
    allowedRoots: ["/srv/workspace"],
    maxRequestsPerWindow: 1_000_000,
    rules: [
      {
        id: "bench-allow-ops",
        effect: "ALLOW",
        roles: ["sre-agent"],
        operations: ["tool"],
        targets: ["fs:read_file", "logs:tail", "web:fetch"]
      }
    ]
  });

  const warden = new McpWarden(
    {
      ...basePreset,
      unicode: { enabled: true },
      egress: { enabled: true, action: "REDACT" },
      hmacAudit: { secretKey: hmacSecret, keyId: "bench-k1" }
    },
    { maxMemoryAuditEntries: 1_000 }
  );

  const context: ExecutionContext = {
    principalId: "bench-sre-01",
    roles: ["sre-agent"],
    sessionId: "bench-v1-1-session"
  };

  await warden.inspectToolsList(
    "bench-upstream-mcp",
    [
      { name: "fs:read_file", description: "Reads workspace files." },
      { name: "logs:tail", description: "Tails service diagnostic logs." },
      { name: "web:fetch", description: "Fetches external HTTPS docs." }
    ],
    context
  );

  const wrappedServer = warden.wrap(
    async (
      _rawRequest: unknown,
      invocation: NormalizedMcpInvocation
    ): Promise<JsonRpcSuccessResponse<{ readonly output: string }>> => ({
      jsonrpc: JSONRPC_VERSION,
      id: invocation.requestId,
      result: {
        output:
          invocation.target === "logs:tail"
            ? `2026-11-23T00:00:00Z INFO key=${synthAwsKey} healthy`
            : `Read completed for ${invocation.target}`
      }
    }),
    (): ExecutionContext => context
  );

  const workloads: readonly unknown[] = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/workspace/README.md" }
      }
    },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "logs:tail",
        arguments: { service: "billing-api" }
      }
    },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "fs:read_file",
        arguments: { path: "/srv/workspace/notes_\u202Etxt.sh" }
      }
    },
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "web:fetch",
        arguments: { url: "http://[::ffff:169.254.169.254]/latest/meta-data/" }
      }
    }
  ];

  for (let i = 0; i < warmupIterations; i += 1) {
    await wrappedServer(workloads[i % workloads.length]);
  }

  const heapStart = process.memoryUsage().heapUsed;
  const latenciesMs: number[] = [];
  const tStart = performance.now();

  for (let i = 0; i < iterations; i += 1) {
    const req = workloads[i % workloads.length];
    const callStart = performance.now();
    await wrappedServer(req);
    latenciesMs.push(performance.now() - callStart);
  }

  const elapsedMs = performance.now() - tStart;
  const heapDeltaKiB = Math.round(
    (process.memoryUsage().heapUsed - heapStart) / 1024
  );

  latenciesMs.sort((a, b) => a - b);

  const p50 = percentile(latenciesMs, 50);
  const p95 = percentile(latenciesMs, 95);
  const p99 = percentile(latenciesMs, 99);
  const opsPerSec = Math.round((iterations / elapsedMs) * 1_000);

  const ndjson = warden.exportAuditNdjson();
  const auditVerify = await verifyAuditNdjson(ndjson, {
    allowSubchain: true,
    hmacSecretOrKeyRing: { secretKey: hmacSecret, keyId: "bench-k1" }
  });
  const metrics = warden.getMetrics();

  console.log("=== mcp-warden v1.1.0 Full-Duplex + HMAC-SHA256 Benchmark ===");
  console.log(`Runtime             : Node.js ${process.version} (${process.platform}/${process.arch})`);
  console.log(`Iterations          : ${iterations.toLocaleString()} full-duplex roundtrips`);
  console.log(`Roundtrip p50       : ${p50.toFixed(3)} ms`);
  console.log(`Roundtrip p95       : ${p95.toFixed(3)} ms`);
  console.log(`Roundtrip p99       : ${p99.toFixed(3)} ms`);
  console.log(`Throughput          : ${opsPerSec.toLocaleString()} roundtrips/sec`);
  console.log(`Bounded Heap Delta  : ${heapDeltaKiB} KiB`);
  console.log(`Egress Scrubbed     : ${metrics.totalEgressScrubbed.toLocaleString()} responses`);
  console.log(`HMAC NDJSON Verified: ${String(auditVerify.valid)} (${auditVerify.checkedCount} ring records)`);
}

void runFullDuplexBenchmark();
