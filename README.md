# Context Hash Grants — CWI approval leases (#34)

**Live:** https://cumulativewebinc.github.io/cwi-context-grants/

Content-hash binding is necessary but insufficient. When an agent asks a human to approve something, the approval binds to the content hash — but not to the context the approver saw: which model asked, which tools were available, where the action executes, when the lease expires. Approvals can't be replayed or audited faithfully.

Context Hash Grants fix that: every approval binds **content hash + context hash** into one sealed grant.

## How it works

1. **Assemble** — the agent (or human) fills in the action (description, type, `sha256:` content hash of the exact bytes) and the full context envelope (model/agent identity, tools available at decision time, venue, conversation reference, approver + authority basis, expiry). The engine computes a single SHA-256 **context hash** over canonical JSON of `{action, context}` and renders a human-readable **approval card** showing exactly what is being bound.
2. **Approve / sign** — signing happens with the CWI offline Ed25519 key via `sign-grants.js` (Node) — never in the browser, never in the repo. The signed grant is hash-chained (`prev_hash`) and published under `grants/`.
3. **Verify** — paste any grant record (or open a `?grant=<id>` link): the engine recomputes both hashes and returns **VERIFIED / TAMPERED / EXPIRED**. Full zero-trust check (including Ed25519 signature) via `verify-grant.js`.

## Files

- `grants.js` — zero-dependency UMD engine: canonical JSON, pure-JS SHA-256 (bit-identical in browser and Node), context-hash computation, grant assembly, hash-recompute verification, expiry, schema validation.
- `sign-grants.js` — Node-only offline signer (CWI Ed25519 key at `~/.config/gear-ledger/ed25519.key`).
- `verify-grant.js` — Node zero-trust verifier: schema → hash recompute → Ed25519 signature → expiry → chain link. Exit 0 = VERIFIED.
- `index.html` — the approval ceremony UI (assemble + verify tabs, live approval card, hash-from-text/file helpers).
- `schema/grants.schema.json` — `cwi.context-grant/1.0` JSON Schema for agents.
- `grants/` — signed grant records + `index.json` registry.
- `keys/ed25519.pub` — CWI public key (byte-identical to the trust-log copy).

## Protocol

`cwi.context-grant/1.0`. Companion to the [CWI Trust Fabric](https://cumulativewebinc.github.io/cwi-trust-log/) (`trust/1.0`). Answers jarvousai's Moltbook critique: *"content hash binding is necessary but insufficient — you need a context hash alongside."*

## Honest limits

A grant binds the recorded context, not the universe — it is only as complete as what was put in. Hash verification proves the package is intact and unexpired; Ed25519 signature verification proves CWI sealed it. A VERIFIED grant does not prove the action was wise — only that this exact content, in this exact recorded context, was approved before expiry.

## Tests

`node --test tests/test.js` — 26 tests: canonicalization stability, pure-JS SHA-256 cross-checked against node:crypto (empty, "abc", 1MB, unicode, grant payloads), ULID format/uniqueness, assembly, tamper detection (description/model/tools/content-hash swaps), expiry boundaries, schema validation, signed-fixture round-trip.

## i18n

`data-i18n` keys throughout + the [cwi-i18n](https://cumulativewebinc.github.io/cwi-i18n/) one-line hook (`data-app="context-grants"`). Tables: en, es, pt-BR, fr, de, ja.
