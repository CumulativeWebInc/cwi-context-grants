// CWI Context Hash Grants — test suite (node:test, zero deps). Run: node --test tests/
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const G = require('../grants.js');

const now = Date.parse('2026-09-16T14:00:00Z');
function mkGrant(over = {}) {
  const action = Object.assign({
    description: 'deploy cwi-context-grants v1.0.0 to production',
    type: 'deploy',
    content_hash: 'sha256:' + 'a'.repeat(64),
    content_ref: 'CumulativeWebInc/cwi-context-grants @ main'
  }, over.action || {});
  const context = Object.assign({
    model: 'muse-spark test',
    tools_available: ['exec', 'read', 'write'],
    venue: 'github-pages-deploy',
    conversation_ref: 'test-session',
    assembled_at: '2026-09-16T13:00:00Z',
    expires_at: '2026-09-23T13:00:00Z',
    approver: 'CWI test approver',
    notes: 'test grant'
  }, over.context || {});
  const g = G.assembleGrant(action, context, { grantId: over.grantId || '01J TESTID0000000000000000'.replace(/ /g, ''), prevHash: over.prevHash });
  if (over.keepId) g.grant_id = over.keepId;
  return g;
}
const GOOD_ID = '01J8ABCDEFGHJKMNPQRSTVWXYZ'; // 26 Crockford chars

describe('canonicalization', () => {
  it('is stable under key reordering', () => {
    const a = { z: 1, a: { d: 4, b: 2 }, m: [3, 1] };
    const b = { a: { b: 2, d: 4 }, m: [3, 1], z: 1 };
    assert.equal(G.canon(a), G.canon(b));
  });
  it('handles nested objects and arrays deterministically', () => {
    const v = { b: [{ y: 1, x: 2 }, { a: true }], a: null };
    assert.equal(G.canon(v), '{"a":null,"b":[{"x":2,"y":1},{"a":true}]}');
  });
  it('handles unicode without escaping differences', () => {
    assert.equal(G.sha256hex('héllo wörld 🌍'), createHash('sha256').update('héllo wörld 🌍', 'utf8').digest('hex'));
  });
});

describe('sha256 engine', () => {
  it('matches node:crypto on empty string', () => {
    assert.equal(G.sha256hex(''), createHash('sha256').update('', 'utf8').digest('hex'));
  });
  it('matches node:crypto on "abc"', () => {
    assert.equal(G.sha256hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });
  it('matches node:crypto on a 1MB input', () => {
    const big = 'x'.repeat(1024 * 1024);
    assert.equal(G.sha256hex(big), createHash('sha256').update(big, 'utf8').digest('hex'));
  });
  it('matches node:crypto on canonical grant payload', () => {
    const payload = G.canon({ action: { description: 'd', type: 'deploy', content_hash: 'sha256:' + '0'.repeat(64) }, context: { model: 'm' } });
    assert.equal(G.sha256hex(payload), createHash('sha256').update(payload, 'utf8').digest('hex'));
  });
});

describe('ulid', () => {
  it('has 26 Crockford chars', () => {
    assert.match(G.ulid(), /^[0-9A-HJKMNP-TV-Z]{26}$/);
  });
  it('produces unique ids', () => {
    const ids = new Set(Array.from({ length: 200 }, () => G.ulid()));
    assert.equal(ids.size, 200);
  });
});

describe('assembly', () => {
  it('computes context_hash = sha256 over canonical {action, context}', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    const expected = 'sha256:' + G.sha256hex(G.canon({ action: g.action, context: g.context }));
    assert.equal(g.context_hash, expected);
  });
  it('sets protocol, issuer, GENESIS prev_hash', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    assert.equal(g.protocol, 'cwi.context-grant/1.0');
    assert.equal(g.issuer, 'Cumulative Web Inc');
    assert.equal(g.prev_hash, 'GENESIS');
  });
});

describe('verifyGrant', () => {
  it('VERIFIED for a fresh valid grant', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    const v = G.verifyGrant(g, now);
    assert.equal(v.verdict, 'VERIFIED');
    assert.ok(v.checks.every(c => c.pass));
  });
  it('TAMPERED when action description changes', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    g.action.description = 'deploy SOMETHING ELSE v9.9.9';
    assert.equal(G.verifyGrant(g, now).verdict, 'TAMPERED');
  });
  it('TAMPERED when a context field changes (model swap)', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    g.context.model = 'evil-model-9000';
    assert.equal(G.verifyGrant(g, now).verdict, 'TAMPERED');
  });
  it('TAMPERED when tools_available changes (privilege widening)', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    g.context.tools_available.push('wallet.sign');
    assert.equal(G.verifyGrant(g, now).verdict, 'TAMPERED');
  });
  it('TAMPERED when content_hash is swapped', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    g.action.content_hash = 'sha256:' + 'f'.repeat(64);
    assert.equal(G.verifyGrant(g, now).verdict, 'TAMPERED');
  });
  it('EXPIRED when now is past expires_at', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    const v = G.verifyGrant(g, Date.parse('2026-10-01T00:00:00Z'));
    assert.equal(v.verdict, 'EXPIRED');
  });
  it('EXPIRED exactly at expires_at boundary', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    const v = G.verifyGrant(g, Date.parse('2026-09-23T13:00:00Z'));
    assert.equal(v.verdict, 'EXPIRED');
  });
  it('VERIFIED one second before expiry', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    const v = G.verifyGrant(g, Date.parse('2026-09-23T12:59:59Z'));
    assert.equal(v.verdict, 'VERIFIED');
  });
});

describe('validateSchema', () => {
  it('passes a valid grant', () => {
    assert.deepEqual(G.validateSchema(mkGrant({ keepId: 'grt_' + GOOD_ID })), []);
  });
  it('fails a missing action.description', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID, action: { description: '' } });
    assert.ok(G.validateSchema(g).some(e => e.includes('action.description')));
  });
  it('fails a bad protocol version', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID });
    g.protocol = 'cwi.context-grant/9.9';
    assert.ok(G.validateSchema(g).some(e => e.includes('protocol')));
  });
  it('fails a malformed content_hash', () => {
    const g = mkGrant({ keepId: 'grt_' + GOOD_ID, action: { content_hash: 'md5:abc' } });
    assert.ok(G.validateSchema(g).some(e => e.includes('content_hash')));
  });
});

describe('tamper fixture (dogfood-style signed grant)', () => {
  const signed = require('./fixtures/grant-signed.json');
  it('fixture verifies VERIFIED', () => {
    const v = G.verifyGrant(JSON.parse(JSON.stringify(signed)), Date.parse('2026-09-16T15:00:00Z'));
    assert.equal(v.verdict, 'VERIFIED');
  });
  it('fixture detects tampering', () => {
    const t = JSON.parse(JSON.stringify(signed));
    t.context.venue = 'somewhere-else';
    assert.equal(G.verifyGrant(t, Date.parse('2026-09-16T15:00:00Z')).verdict, 'TAMPERED');
  });
  it('grantHash is stable and chains', () => {
    const h1 = G.grantHash(signed);
    assert.match(h1, /^sha256:[0-9a-f]{64}$/);
    assert.equal(G.grantHash(JSON.parse(JSON.stringify(signed))), h1);
  });
});
