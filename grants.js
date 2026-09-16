/* CWI Context Hash Grants — grant engine v1.0.0 (cwi.context-grant/1.0)
 * Zero-dependency UMD: runs in browsers and Node.
 * - Canonical JSON (recursive key sort, no whitespace)
 * - Pure-JS SHA-256 (bit-identical in every runtime; cross-checked vs node:crypto in tests)
 * - Context-hash computation, grant assembly, hash-recompute verification, expiry, schema validation
 * Signing is intentionally NOT in this file: Ed25519 signing needs the offline CWI key
 * and happens via sign-grants.js (Node) — never in the browser, never in the repo.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CWIGrants = factory();
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var PROTOCOL = 'cwi.context-grant/1.0';
  var ISSUER = 'Cumulative Web Inc';

  // ---- canonical JSON: recursive key sort, no whitespace ----
  function canon(v) {
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
    if (v && typeof v === 'object') {
      return '{' + Object.keys(v).sort().map(function (k) {
        return JSON.stringify(k) + ':' + canon(v[k]);
      }).join(',') + '}';
    }
    return JSON.stringify(v);
  }

  // ---- pure-JS SHA-256 over bytes ----
  var K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

  function sha256Bytes(msg) {
    var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
        h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    var ml = msg.length;
    var bitLen = ml * 8;
    var bitLenHi = Math.floor(bitLen / 4294967296), bitLenLo = bitLen >>> 0;
    var totalLen = (((ml + 9 + 63) >> 6) << 6);
    var p = new Uint8Array(totalLen);
    p.set(msg); p[ml] = 0x80;
    p[totalLen-8]=(bitLenHi>>>24)&255; p[totalLen-7]=(bitLenHi>>>16)&255;
    p[totalLen-6]=(bitLenHi>>>8)&255;  p[totalLen-5]=bitLenHi&255;
    p[totalLen-4]=(bitLenLo>>>24)&255; p[totalLen-3]=(bitLenLo>>>16)&255;
    p[totalLen-2]=(bitLenLo>>>8)&255;  p[totalLen-1]=bitLenLo&255;
    var w = new Uint32Array(64), off, i, a, b, c, d, e, f, g, h, t1, t2, s0, s1, S0, S1, ch, maj;
    for (off = 0; off < totalLen; off += 64) {
      for (i = 0; i < 16; i++)
        w[i] = (p[off+i*4]<<24)|(p[off+i*4+1]<<16)|(p[off+i*4+2]<<8)|p[off+i*4+3];
      for (i = 16; i < 64; i++) {
        s0 = ((w[i-15]>>>7)|(w[i-15]<<25))^((w[i-15]>>>18)|(w[i-15]<<14))^(w[i-15]>>>3);
        s1 = ((w[i-2]>>>17)|(w[i-2]<<15))^((w[i-2]>>>19)|(w[i-2]<<13))^(w[i-2]>>>10);
        w[i] = (w[i-16]+s0+w[i-7]+s1)|0;
      }
      a=h0;b=h1;c=h2;d=h3;e=h4;f=h5;g=h6;h=h7;
      for (i = 0; i < 64; i++) {
        S1 = ((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
        ch = (e&f)^(~e&g);
        t1 = (h+S1+ch+K[i]+w[i])|0;
        S0 = ((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
        maj = (a&b)^(a&c)^(b&c);
        t2 = (S0+maj)|0;
        h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
      }
      h0=(h0+a)|0;h1=(h1+b)|0;h2=(h2+c)|0;h3=(h3+d)|0;
      h4=(h4+e)|0;h5=(h5+f)|0;h6=(h6+g)|0;h7=(h7+h)|0;
    }
    var out = new Uint8Array(32), hs = [h0,h1,h2,h3,h4,h5,h6,h7];
    for (i = 0; i < 8; i++) {
      out[i*4]=(hs[i]>>>24)&255; out[i*4+1]=(hs[i]>>>16)&255;
      out[i*4+2]=(hs[i]>>>8)&255; out[i*4+3]=hs[i]&255;
    }
    return out;
  }

  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    // Node < 11 fallback via Buffer
    return new Uint8Array(Buffer.from(str, 'utf8'));
  }

  function hex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      var x = bytes[i].toString(16);
      s += x.length === 1 ? '0' + x : x;
    }
    return s;
  }

  function sha256hex(str) { return hex(sha256Bytes(utf8(str))); }

  // ---- ULID (Crockford base32, time-ordered) ----
  var CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function ulid() {
    var t = Date.now(), s = '', i;
    for (i = 0; i < 10; i++) { s = CROCK[t % 32] + s; t = Math.floor(t / 32); }
    var r = '', rnd;
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      rnd = crypto.getRandomValues(new Uint8Array(16));
    } else {
      rnd = new Uint8Array(16);
      for (i = 0; i < 16; i++) rnd[i] = Math.floor(Math.random() * 256);
    }
    for (i = 0; i < 16; i++) r += CROCK[rnd[i] % 32];
    return s + r;
  }

  // ---- grant assembly ----
  // action: {description, type, content_hash, content_ref?}
  // context: {model, tools_available[], venue, conversation_ref?, assembled_at, expires_at, approver, notes?}
  function computeContextHash(action, context) {
    return 'sha256:' + sha256hex(canon({ action: action, context: context }));
  }

  function assembleGrant(action, context, opts) {
    opts = opts || {};
    var a = {
      description: String(action.description || ''),
      type: String(action.type || 'other'),
      content_hash: String(action.content_hash || '')
    };
    if (action.content_ref) a.content_ref = String(action.content_ref);
    var tools = Array.isArray(context.tools_available) ? context.tools_available.map(String) : [];
    var c = {
      model: String(context.model || ''),
      tools_available: tools,
      venue: String(context.venue || ''),
      assembled_at: String(context.assembled_at || ''),
      expires_at: String(context.expires_at || ''),
      approver: String(context.approver || '')
    };
    if (context.conversation_ref) c.conversation_ref = String(context.conversation_ref);
    if (context.notes) c.notes = String(context.notes);
    return {
      protocol: PROTOCOL,
      grant_id: 'grt_' + (opts.grantId || ulid()),
      action: a,
      context: c,
      context_hash: computeContextHash(a, c),
      issuer: ISSUER,
      prev_hash: opts.prevHash || 'GENESIS'
      // signature added by sign-grants.js (offline key) — never here
    };
  }

  // grant hash for chaining: sha256 over canonical payload (everything except signature)
  function grantHash(grant) {
    var payload = {};
    Object.keys(grant).sort().forEach(function (k) {
      if (k !== 'signature') payload[k] = grant[k];
    });
    return 'sha256:' + sha256hex(canon(payload));
  }

  // ---- structural validation (cwi.context-grant/1.0) ----
  var ACTION_TYPES = ['deploy','publish','payment','config-change','submission','access-grant','other'];
  function validateSchema(g) {
    var errs = [];
    if (!g || typeof g !== 'object') return ['grant must be an object'];
    if (g.protocol !== PROTOCOL) errs.push('protocol must be "' + PROTOCOL + '"');
    if (!/^grt_[0-9A-HJKMNP-TV-Z]{26}$/.test(g.grant_id || '')) errs.push('grant_id malformed');
    var a = g.action || {};
    if (!a.description || typeof a.description !== 'string') errs.push('action.description required');
    if (ACTION_TYPES.indexOf(a.type) < 0) errs.push('action.type must be one of ' + ACTION_TYPES.join(','));
    if (!/^sha256:[0-9a-f]{64}$/.test(a.content_hash || '')) errs.push('action.content_hash must be sha256:<64 hex>');
    var c = g.context || {};
    ['model','venue','assembled_at','expires_at','approver'].forEach(function (k) {
      if (!c[k] || typeof c[k] !== 'string') errs.push('context.' + k + ' required');
    });
    if (!Array.isArray(c.tools_available)) errs.push('context.tools_available must be an array');
    if (c.assembled_at && isNaN(Date.parse(c.assembled_at))) errs.push('context.assembled_at not a date');
    if (c.expires_at && isNaN(Date.parse(c.expires_at))) errs.push('context.expires_at not a date');
    if (!/^sha256:[0-9a-f]{64}$/.test(g.context_hash || '')) errs.push('context_hash must be sha256:<64 hex>');
    if (g.issuer !== ISSUER) errs.push('issuer must be "' + ISSUER + '"');
    if (typeof g.prev_hash !== 'string' || !g.prev_hash) errs.push('prev_hash required');
    return errs;
  }

  // ---- verification: recompute hashes, check expiry ----
  // returns {verdict: 'VERIFIED'|'TAMPERED'|'EXPIRED', checks: [...]}
  function verifyGrant(grant, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var checks = [];
    function check(name, pass, detail) { checks.push({ name: name, pass: !!pass, detail: detail || '' }); }

    var schemaErrs = validateSchema(grant);
    check('schema', schemaErrs.length === 0, schemaErrs.join('; ') || 'cwi.context-grant/1.0 structure OK');

    var recomputed = null, hashOk = false;
    if (grant && grant.action && grant.context) {
      recomputed = computeContextHash(grant.action, grant.context);
      hashOk = (recomputed === grant.context_hash);
    }
    check('context_hash_recompute', hashOk,
      hashOk ? 'recomputed hash matches bound context_hash'
             : 'MISMATCH — expected ' + grant.context_hash + ', recomputed ' + recomputed);

    var exp = grant && grant.context ? Date.parse(grant.context.expires_at) : NaN;
    var expired = isNaN(exp) ? true : now >= exp;
    check('expiry', !expired,
      isNaN(exp) ? 'expires_at unparseable — treated as expired'
                 : (expired ? 'expired at ' + grant.context.expires_at : 'valid until ' + grant.context.expires_at));

    var verdict = 'VERIFIED';
    if (!hashOk || schemaErrs.length > 0) verdict = 'TAMPERED';
    else if (expired) verdict = 'EXPIRED';
    return { verdict: verdict, checks: checks };
  }

  return {
    PROTOCOL: PROTOCOL,
    ISSUER: ISSUER,
    canon: canon,
    sha256hex: sha256hex,
    sha256Bytes: sha256Bytes,
    ulid: ulid,
    computeContextHash: computeContextHash,
    assembleGrant: assembleGrant,
    grantHash: grantHash,
    validateSchema: validateSchema,
    verifyGrant: verifyGrant,
    ACTION_TYPES: ACTION_TYPES
  };
}));
