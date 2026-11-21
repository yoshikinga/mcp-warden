import {
  McpWarden,
  verifyAuditChain,
  type AuditEntry,
  type AuditSink,
  type ExecutionContext
} from "../src/index.js";

async function runEnterpriseRbacAuditDemo(): Promise<void> {
  const siemExportBuffer: AuditEntry[] = [];

  // Custom SIEM / compliance log sink receiving real-time sealed SHA-256 records
  const siemAuditSink: AuditSink = {
    write(entry: AuditEntry): void {
      siemExportBuffer.push(entry);
    }
  };

  const warden = new McpWarden(
    {
      rules: [
        {
          id: "deny-prod-drop-globally",
          effect: "DENY",
          roles: ["*"],
          operations: ["tool"],
          targets: ["db:drop_*", "infra:destroy_*"]
        },
        {
          id: "allow-tier1-bounded-customer-lookup",
          effect: "ALLOW",
          roles: ["support-tier1"],
          operations: ["tool"],
          targets: ["crm:get_customer"],
          argumentConstraints: {
            region: { required: true, type: "string", enum: ["us-east", "eu-west"] },
            maxRecords: { required: true, type: "number", min: 1, max: 25 }
          }
        }
      ],
      rateLimit: {
        windowMs: 60_000,
        maxRequestsPerWindow: 20,
        targetOverrides: {
          "crm:get_customer": 2
        }
      },
      sensitiveAuditKeys: ["supportSessionSecret"]
    },
    {
      auditSinks: [siemAuditSink]
    }
  );

  const tier1Agent: ExecutionContext = {
    principalId: "svc-support-bot",
    roles: ["support-tier1"],
    sessionId: "ticket-98412"
  };

  // Call 1: Valid bounded lookup (credentials automatically redacted in audit log)
  const first = await warden.inspect(
    {
      jsonrpc: "2.0",
      id: "c-1",
      method: "tools/call",
      params: {
        name: "crm:get_customer",
        arguments: {
          region: "us-east",
          maxRecords: 10,
          apiKey: "sk-live-enterprise-token",
          supportSessionSecret: "top-secret-session"
        }
      }
    },
    tier1Agent
  );
  console.log("Call 1 Allowed:", first.allowed, "| Redacted Args:", first.auditEntry.redactedArguments);

  // Call 2: Argument constraint violation (maxRecords = 500 > 25)
  const second = await warden.inspect(
    {
      jsonrpc: "2.0",
      id: "c-2",
      method: "tools/call",
      params: {
        name: "crm:get_customer",
        arguments: { region: "us-east", maxRecords: 500 }
      }
    },
    tier1Agent
  );
  console.log("Call 2 Allowed:", second.allowed, "| Reason:", second.auditEntry.reasonCode);

  // Call 3: Per-tool sliding-window rate limit exceeded (3rd call > override quota of 2)
  const third = await warden.inspect(
    {
      jsonrpc: "2.0",
      id: "c-3",
      method: "tools/call",
      params: {
        name: "crm:get_customer",
        arguments: { region: "eu-west", maxRecords: 5 }
      }
    },
    tier1Agent
  );
  console.log("Call 3 Allowed:", third.allowed, "| Reason:", third.auditEntry.reasonCode);

  const integrityReport = await verifyAuditChain(siemExportBuffer);
  console.log("External SIEM Chain Verification:", integrityReport);
}

void runEnterpriseRbacAuditDemo();
