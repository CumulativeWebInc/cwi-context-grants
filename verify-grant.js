#!/usr/bin/env node
// CWI Context Hash Grants — zero-trust verifier (Node, zero dependencies).
// Usage: node verify-grant.js <grant.json> [grants-index.json]
// Checks: schema -> context-hash recompute -> Ed25519 signature -> expiry -> chain link.
// Exit 0 = VERIFIED, 1 = TAMPERED/EXPIRED, 2 = usage error.
import { readFileSync } from 'node:fs';
import { createPublicKey, verify, createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const G = require('./grants.js');
const HERE = dirname(fileURLToPath(import.meta.url));

const file = process.argv[2];
if (!file) { console.error('usage: node verify-grant.js <grant.json> [grants-index.json]'); process.exit(2); }
const grant = JSON.parse(readFileSync(file, 'utf8'));
const indexFile = process.argv[3];

let verdict = 'VERIFIED';
const fails = [];

// 1. hash recompute + schema + expiry (engine)
const v = G.verifyGrant(grant);
for (const c of v.checks) {
  console.log((c.pass ? 'PASS' : 'FAIL') + '  ' + c.name + (c.detail ? ' — ' + c.detail : ''));
  if (!c.pass) fails.push(c.name);
}

// 2. Ed25519 signature against the published CWI public key
try {
  const pubPem = readFileSync(join(HERE, 'keys/ed25519.pub'), 'utf8');
  const pub = createPublicKey(pubPem);
  const payload = {};
  Object.keys(grant).sort().forEach(k => { if (k !== 'signature' && k !== 'grant_hash') payload[k] = grant[k]; });
  const ok = grant.signature
    ? verify(null, Buffer.from(G.canon(payload), 'utf8'), pub, Buffer.from(grant.signature, 'base64'))
    : false;
  console.log((ok ? 'PASS' : 'FAIL') + '  ed25519_signature' + (ok ? ' — signed by CWI offline key' : ' — MISSING or INVALID'));
  if (!ok) fails.push('ed25519_signature');
} catch (e) {
  console.log('FAIL  ed25519_signature — ' + e.message);
  fails.push('ed25519_signature');
}

// 3. chain link (optional index)
if (indexFile) {
  try {
    const idx = JSON.parse(readFileSync(indexFile, 'utf8'));
    const ids = (idx.grants || []).map(g => g.grant_id);
    const pos = ids.indexOf(grant.grant_id);
    if (pos < 0) { console.log('FAIL  chain_membership — grant_id not in index'); fails.push('chain_membership'); }
    else {
      const expectedPrev = pos === 0 ? 'GENESIS' : idx.grants[pos - 1].grant_hash;
      const ok = grant.prev_hash === expectedPrev;
      console.log((ok ? 'PASS' : 'FAIL') + '  chain_link — prev_hash ' + (ok ? 'matches predecessor' : 'MISMATCH'));
      if (!ok) fails.push('chain_link');
    }
  } catch (e) { console.log('FAIL  chain_link — ' + e.message); fails.push('chain_link'); }
}

// 4. cross-check pure-JS sha256 against node:crypto on the context payload
const ref = createHash('sha256').update(G.canon({ action: grant.action, context: grant.context }), 'utf8').digest('hex');
const mine = G.sha256hex(G.canon({ action: grant.action, context: grant.context }));
const okHash = ref === mine && ('sha256:' + mine) === grant.context_hash;
console.log((okHash ? 'PASS' : 'FAIL') + '  sha256_crosscheck — pure-JS engine matches node:crypto');
if (!okHash) fails.push('sha256_crosscheck');

if (v.verdict !== 'VERIFIED') fails.push('verdict:' + v.verdict);
console.log('---');
console.log('VERDICT: ' + (fails.length ? 'TAMPERED/EXPIRED' : 'VERIFIED'));
process.exit(fails.length ? 1 : 0);
