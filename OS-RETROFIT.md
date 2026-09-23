# OS Retrofit — Context Hash Grants (slot 19)

Date: 2026-09-23 · OPERATION RETROFIT Wave 2 · Constitution: AGENT-OPERATING-FRAMEWORK-2026-09-23

## What changed (this retrofit)
- Brand: official CWI logo (`brand/logo.jpg`) in the page header; Cumulative Web Inc header/footer identity on every page.
- CTA + try-link: visible "Try it live" strip with a working deep link, plus a business/support secondary CTA.
- Metadata: `llms.txt`, `.well-known/agent-card.json`, `content.json`, JSON-LD `WebApplication` schema.org block, canonical + Open Graph + Twitter tags.
- Marketing: value proposition above the fold; honest-limits copy retained verbatim (truth labels NEVER upgraded).
- Business: $0 free tool; commercial/support route via hp@cumulativeweb.com; attribution via the app's own machine-readable receipts and deep links (no third-party trackers).
- OS fit: nervous-system project state `os-retrofit-19-context-grants` with evidence-graded claims; 21-gate theorem verdict recorded.

## Red-team pass (2026-09-23)
- Signing key stays off-repo: sign-grants.js reads ~/.config/gear-ledger/ed25519.key (or GEAR_LEDGER_KEY); keys/ ships the PUBLIC key only. Secret scan: 0 hits.
- Grant verify UI renders pasted JSON through esc() — no XSS from pasted grant records.
- Additive-only protocol: verification can mark TAMPERED/EXPIRED but the registry never rewrites or invalidates published grants.

## Secret scan (2026-09-23)
Pattern scan over the full repo (api keys, secrets, tokens, private keys): **0 hits**.
Signing key: private key off-repo at ~/.config/gear-ledger/ed25519.key — never committed, never printed.

## Tests
node --test tests/test.js — 26/26

## Truth-label discipline
No label changed in this retrofit. UNVERIFIED stays UNVERIFIED; honest-limits copy untouched.
