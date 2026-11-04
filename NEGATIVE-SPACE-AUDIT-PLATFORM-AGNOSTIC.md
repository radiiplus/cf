# Negative-Space Audit — Platform-Agnostic Methodology

A reusable method for auditing **any** API platform by mapping what it rejects, masks, transforms, or never exposes. It is intentionally independent of vendor, language, and network topology: the only assumptions are that the platform has an observable request/response contract and that you are authorized to test it.

The core idea: stop trying to breach infrastructure. Treat the **response layer itself as the oracle**. Submit synthesized data that is valid at every stage except exactly one, through every available entry point, and read the platform's implementation from how it answers.

---

## 1. Definitions

| Term | Meaning |
|---|---|
| **Positive space** | Everything the platform documents, accepts, and returns successfully. |
| **Negative space** | Everything the platform rejects, silently normalizes, hides behind a generic error, or never exposes through any surface. |
| **Producer** | Any actor or layer that can generate input: a client, SDK, browser, mobile app, webhook sender, another service, an operator, or the operating system beneath the platform. |
| **Oracle** | A response whose shape lets you distinguish one internal behavior from another. |
| **Layer** | An independently observable stage of processing: edge, gateway, application framework, business logic, datastore, downstream service. |
| **Masked** | A behavior that exists but cannot be observed without credentials or state you do not have. Record it as masked, never as absent. |

The negative space is not "untested code". It is the set of inputs and states that the platform's own producers cannot generate, plus the states it generates internally but never exposes.

---

## 2. Principles

1. **Framework first, evasion never.** Identify the framework and its contract before probing. The framework's validation pipeline defines the negative space.
2. **Valid envelope + one negative.** Keep auth shape, content type, route, and required fields valid so the probe reaches the inner validator. Change exactly one dimension.
3. **Layer separation.** Classify every rejection as edge/WAF, gateway, application, or downstream. The layer that rejects tells you what exists behind it.
4. **Execute the platform's own client.** Public SDKs, CLIs, MCP servers, and mobile bundles are the exact request constructors; run them with calibrated fake credentials.
5. **State is part of the space.** Replays, nonces, timestamps, idempotency keys, cursors, and connection reuse are audit dimensions, not edge cases.
6. **Evidence over intuition.** Every claim is `PROVEN` (observed directly, with a transcript) or `INFERRED` (indirect, with the evidence pointer). Never rank by plausibility alone.
7. **Authorization and non-mutation.** Only test surfaces you own or are explicitly allowed to test. Use fake credentials on state-changing routes; never move funds, exfiltrate content, or touch third-party data.

---

## 3. The audit model

```
producer ──► transport/edge ──► gateway ──► framework ──► business logic ──► datastore/downstream
                 │                 │             │                 │
              rejection        masking       validation         state change
                 └───────────────┴─────────────┴─────────────────┘
                              observable response layer
```

For every request, record **invariant** (what you sent), **reaction** (status, headers, body, timing, connection behavior), and **layer** (where the reaction originated). The gap between expected and observed is the finding.

---

## 4. Phase 0 — Contract extraction (static, no probing)

Goal: build a machine-readable model of what the platform claims to accept before touching it.

- Obtain the official client source: SDKs, CLI tools, MCP/agent packages, mobile bundles, public docs, OpenAPI/AsyncAPI/GraphQL schemas, Postman collections, changelogs.
- Extract per route/message:
  - transport, method, path, content type;
  - required vs optional fields, declared types, enums, formats, limits;
  - auth scheme and signature preimage (field order, encoding, what is and is not signed);
  - nonce format, timestamp unit, idempotency keys, pagination cursors;
  - error envelope shape and documented error codes.
- Diff documentation against client code. Every mismatch is a candidate negative.
- Output: `contract.json` or a structured table, one row per route/message.

**Platform adapters:** REST/OpenAPI, GraphQL introspection or schema files, gRPC/protobuf descriptors, WebSocket frame schemas, webhook payload specs, CLI help, mobile bundle strings.

---

## 5. Phase 1 — Baseline and oracle calibration (dynamic)

Goal: establish what "normal" looks like so a negative can be recognized.

- Run the official client against the live plane with **calibrated fake credentials** and with **no credentials**.
- Capture:
  - successful response envelope and headers;
  - trace/request-id headers, server tokens, rate-limit headers;
  - error serialization for each auth state;
  - connection behavior (keep-alive, TLS, WS upgrade, close codes).
- Build **oracles**:
  - absent credential vs malformed credential vs well-formed-but-unknown credential;
  - valid route vs unknown route vs known route with wrong method;
  - valid enum vs unknown enum;
  - empty body vs malformed body vs valid body.
- Record the **auth-gate order** you can observe. Everything after the first failing gate is masked until you have valid credentials.
- Re-run the baseline whenever the environment, region, tenant, or client version changes.

---

## 6. Phase 2 — Negative taxonomy (generate the probe set)

For every route and every parameter, generate probes across these classes:

### 6.1 Value-level
- **Type confusion:** array vs scalar, object vs string, integer vs string, boolean, null, nested depth.
- **Boundary values:** empty string, zero, negative, max-int, overflow, scientific notation, `NaN`/`Infinity`, 10k+ character strings, unicode, emoji, combining characters, null bytes.
- **Enum gaps:** unknown values, case variants, separator variants (`-` vs `_`), plausible-but-undeclared values, deprecated values.
- **Format violations:** malformed dates, timestamps, UUIDs, currencies, symbols, addresses, phone numbers, emails.
- **Field manipulation:** missing required fields, unknown/extra fields, duplicate keys, class-hint keys (`__class`, `@type`), deeply nested unknown objects.
- **Encoding:** single/double URL encoding, unicode normalization, path traversal compounds, query/fragment split, header injection patterns.

### 6.2 Structural / protocol
- Wrong method; missing/extra path segments; trailing slash; case changes; dot-segment normalization.
- Content-type mismatches and charset variants.
- Multipart boundary abuse; filename/path fields; oversized parts.
- WebSocket/SSE/gRPC: wrong op, missing args, scalar vs array, unknown channel, malformed frame, login frame on public plane, ping on private plane.
- HTTP/2 vs HTTP/1.1 behavior; header order/casing; duplicate headers; chunked vs fixed length.

### 6.3 State / sequence
- Exact replay (same nonce/timestamp/signature).
- Nonce collision, timestamp drift (±30s/2m/5m/15m/1h), future timestamps.
- Duplicate submission with/without idempotency key.
- Out-of-order calls, skipped steps, re-used one-time tokens, expired sessions.
- Connection reuse with mixed valid/invalid frames.

### 6.4 Resource / economics (where applicable)
- Cost charged vs work performed; page/instruction/cycle/syscall counts.
- Rate-limit accounting, quota resets, concurrency limits.
- Cache keys, pagination cursors, ID generation and enumeration.
- Only proceed when a probe can plausibly move amplification or conversion; drop probes that cannot.

### 6.5 Metadata / observational
- `OPTIONS` responses and `Allow` headers as route-existence oracles.
- Error pages, stack fragments, internal hostnames, class names, SQL fragments, file paths.
- Response timing deltas as a proxy for validation order or data existence.
- Server-generated identifiers and their formats.

---

## 7. Phase 3 — Mixed-input submission

- Submit each probe with the **valid envelope preserved**; only the target dimension is negative.
- Cover every entry-point class: REST, GraphQL, WebSocket, SSE, gRPC, file upload, auth/OAuth, webhooks, admin/partner planes, mobile and CLI paths, and any staging/demo twins.
- Use a controlled matrix so each probe's provenance is reproducible: probe ID, route, field, class, expected layer, raw request, raw response, timestamp.
- Non-mutating discipline: fake credentials for state-changing routes; own-account sessions only where authorized; stop at the auth boundary unless explicitly scoped.
- Throttle and randomize to avoid rate-limit contamination; distinguish rate-limit responses from application responses.

---

## 8. Phase 4 — Response-layer mining

From each response, extract:

- **Validator map:** per route and field, the accepted/rejected types, ordering, and error codes.
- **Error dictionary:** code → message → meaning, including codes never observed (gaps imply undocumented behavior).
- **Framework fingerprints:** error-page shapes, envelope grammar, status-masking, `Allow` headers, default 404/405 pages, serialization quirks.
- **Leakage:** stack fragments, internal hostnames, class/library names, SQL or template fragments, file paths, build IDs.
- **Layer classification:** edge HTML block vs gateway JSON vs application error vs downstream timeout.
- **Normalization behavior:** what is collapsed, trimmed, re-encoded, or silently ignored before validation.

Record the **same** response shape across sibling planes and tenants to infer shared deployment families.

---

## 9. Phase 5 — Statefulness and memory tests

- **Replay:** identical request accepted or rejected?
- **Nonce/timestamp:** is the nonce tracked? Where is the freshness cutoff? Are future timestamps accepted?
- **Idempotency:** is the key honored, ignored, or scoped incorrectly?
- **Session fixation / rotation:** does privilege change rotate identifiers?
- **Connection state (WS/SSE):** what survives across frames? Capture the close-code ladder.
- **Server identifiers:** are request IDs echoed, predictable, or enumerable?
- **Cache behavior:** does a response depend on a header, cookie, or query parameter in an unintended way?

Classify each as **stateless**, **stateful-safe**, **stateful-unsafe**, or **masked**.

---

## 10. Phase 6 — Auth-gate ordering inference

- Group negative classes by whether they produce distinct responses or collapse into one generic auth failure.
- Infer the pipeline order, e.g. route match → method → content type → key existence → signature → timestamp → nonce → permission → business validation.
- Anything after the first failing gate is **masked**, not absent.
- Repeat with a valid low-privilege credential (if authorized) to reveal the next gate.
- Diagram the pipeline with explicit masked regions.

---

## 11. Phase 7 — Protocol-specific negatives

### WebSocket / realtime
- Frame shape: op as array/object/missing; args as scalar/empty; unknown ops/channels; missing required fields; type-confused values.
- Auth: login frame on public plane, public frame on private plane, re-auth mid-stream.
- Observe: subscribe echo, error frames echoing the original frame, silent drops, close codes.

### GraphQL
- Unknown fields, wrong types, aliases, fragments, directives, deeply nested queries, introspection toggles, batching, query cost limits.
- Error paths and `extensions` blobs for resolver/framework leakage.

### gRPC
- Unknown method, wrong message type, missing fields, oversized messages, metadata handling, streaming half-close, status code/detail leakage.

### Files / uploads
- Filename/path handling, content-type vs magic bytes, size limits, archive recursion, presigned URL scope and expiry, storage bucket listing.

### Webhooks / async
- Signature preimage, replay window, ordering, duplicate delivery, URL validation (SSRF), redirect handling, content-type confusion.

---

## 12. Phase 8 — Synthesis and scoring

Produce findings that are reproducible and comparable across platforms.

- **Severity inputs:** impact (confidentiality/integrity/availability/economics), reachability, authorization required, reliability, and whether the effect crosses a trust boundary.
- **Confidence:** `PROVEN` with transcript vs `INFERRED` with evidence chain.
- **Coverage:** percentage of routes, parameters, and producer classes exercised; list what remains masked.
- **Deduplicate:** one finding per root cause, not per probe.
- **Drop:** probes that cannot move a real quantity, probes that require a victim to act, probes that only produce plausibility.

Suggested score for economic probes: `score = A × K`, where `A = real_work / charged_cost` and `K = value_under_attacker_control / charged_cost`, subject to zero variance and repeatability. Do not report a bare amplification without a conversion path.

---

## 13. Output artifacts

1. `contract.json` — routes/messages, fields, types, enums, auth schemes.
2. `validator-map.md` — per route/field accepted vs rejected, with codes.
3. `layer-matrix.md` — negative class × layer × response.
4. `error-dictionary.md` — codes, messages, meanings, gaps.
5. `framework-fingerprints.md` — per-plane stack with PROVEN/INFERRED.
6. `statefulness-report.md` — replay, nonce, timestamp, idempotency, connection state.
7. `auth-gate-order.md` — pipeline diagram with masked regions.
8. `leakage-register.md` — every internal name/path/identifier observed, with redaction.
9. `coverage.md` — what was tested, what was masked, what was out of scope.
10. `findings.md` — deduplicated, scored, reproducible.
11. `transcripts/` — raw request/response pairs, one per probe ID.

---

## 14. Reusability checklist (any platform)

- [ ] Authorization explicitly scoped and recorded.
- [ ] Official client/schema obtained and diffed against docs.
- [ ] Baseline captured for absent / malformed / valid credentials.
- [ ] Negative taxonomy applied to every route and field.
- [ ] Probes preserve the valid envelope.
- [ ] Every probe has an ID, transcript, and layer classification.
- [ ] Masked behavior is labeled, never guessed.
- [ ] Cross-plane and cross-tenant parity checked where available.
- [ ] Findings deduplicated, scored, and reproducible.
- [ ] No third-party data, funds, or credentials touched.
- [ ] Redaction applied to any leaked internal identifiers before sharing.

---

## 15. Common pitfalls

- Treating a WAF/HTML block page as an application error.
- Assuming an always-200 gateway means success; read the in-body code.
- Assuming a generic auth error means the route does not exist.
- Confusing rate limiting with validation.
- Over-fitting to one tenant or one client version.
- Reporting a negative as absent when it is only masked.
- Reporting amplification without a conversion path.
- Letting a source-code hypothesis drive the probe set; observe first, explain later.

---

## 16. Why this works

Frameworks are deterministic pipelines: parse, normalize, validate, authenticate, authorize, execute, serialize. Each stage has a characteristic failure signature. By submitting inputs that are valid at every stage except exactly one, you force each stage to announce itself through its response. The negative space — everything the platform refuses or hides — is a precise blueprint of its internals, obtained entirely through the response layer, with no network-stack targeting and no need for the source.
