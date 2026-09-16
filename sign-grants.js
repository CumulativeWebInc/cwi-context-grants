#!/usr/bin/env node
// CWI Context Hash Grants — offline signer.
// Signs an assembled (unsigned) grant package with the CWI Ed25519 key.
// Private key: ~/.config/gear-ledger/ed25519.key — NEVER committed, NEVER printed.
// Usage: node sign-grants.js <unsigned-grant.json> [--prev <prev_hash>] > signed.json
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, sign } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const G = require('./grants.js');

const KEY_PATH = process.env.GEAR_LEDGER_KEY || join(homedir(), '.config/gear-ledger/ed25519.key');

function signPayload(canonicalBytes) {
  const key = createPrivateKey(readFileSync(KEY_PATH, 'utf8'));
  return sign(null, Buffer.from(canonicalBytes, 'utf8'), key).toString('base64');
}

const file = process.argv[2];
if (!file) { console.error('usage: node sign-grants.js <unsigned-grant.json> [--prev <prev_hash>]'); process.exit(2); }
const prevIdx = process.argv.indexOf('--prev');
const prevHash = prevIdx > 0 ? process.argv[prevIdx + 1] : 'GENESIS';

const grant = JSON.parse(readFileSync(file, 'utf8'));
grant.prev_hash = prevHash;
const errs = G.validateSchema(grant);
if (errs.length) { console.error('schema errors: ' + errs.join('; ')); process.exit(1); }
// re-derive context hash to guarantee it binds what we sign
grant.context_hash = G.computeContextHash(grant.action, grant.context);

const payload = {};
Object.keys(grant).sort().forEach(k => { if (k !== 'signature') payload[k] = grant[k]; });
const canonical = G.canon(payload);
grant.signature = signPayload(canonical);
grant.grant_hash = G.grantHash(grant); // informational; not part of signed payload

process.stdout.write(JSON.stringify(grant, null, 2) + '\n');
console.error('signed ' + grant.grant_id + ' context_hash=' + grant.context_hash.slice(0, 19) + '…');
