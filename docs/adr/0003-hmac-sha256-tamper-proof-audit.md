# ADR 0003: Secret-Keyed HMAC-SHA256 Audit Chain & Canonical NDJSON

- **Status:** Accepted
- **Date:** 2026-11-23
- **Deciders:** `@yoshikinga` Core Architecture

## Context

In `v1.0.0`, `AuditLogger` linked every decision using unkeyed `SHA-256(prevHash + "|" + canonicalJson(entry))`. While unkeyed hash chains reliably expose accidental corruption, mid-chain edits, or single-line deletions, a privileged attacker who gains write access to the log file can rewrite `sequence: 0` from `GENESIS_PREV_HASH` and recompute valid unkeyed SHA-256 hashes for a forged history.

Enterprise compliance teams (SOC2 Type II, ISO 27001, HIPAA) also require:

- Zero-downtime cryptographic key rotation across quarters.
- Protection against tail-truncation (dropping the most recent `DENY` alerts).
- Line-oriented SIEM ingestion compatible with Splunk, Datadog, and Elastic without custom binary parsers.

## Decision

1. **Layered `HMAC-SHA256` Authentication (`src/audit/hmac-signer.ts`):** When `hmacAudit` is configured, each SHA-256-sealed record is additionally signed using Web Crypto `HMAC` (`SHA-256`) over `${keyId}|${sequence}\vert{}${prevHash}|${hash}\vert{}${canonicalJson(unsignedEntry)}`.
2. **Cached `CryptoKey` & Key-Ring Rotation:** `HmacAuditSigner` caches the non-extractable `CryptoKey` promise for sub-millisecond signing, while `verifySignedAuditChain()` accepts a `{ [keyId]: secretKey }` dictionary so historical logs remain verifiable across key rotations.
3. **Tail-Truncation Anchors & Canonical NDJSON (`src/audit/ndjson-codec.ts`):** Verification supports `expectedCount` and `expectedLastHash` anchors, serialized as RFC 8785 key-sorted **NDJSON** verifiable standalone via `npx mcp-warden verify-audit`.

## Consequences

- **Positive:** Elevates audit logs from *tamper-evident* to *cryptographically unforgeable* without external KMS SDK dependencies.
- **Trade-off:** Operators enabling `hmacAudit` must provision and protect the signing secret via environment variables or secret managers outside the log storage volume.
