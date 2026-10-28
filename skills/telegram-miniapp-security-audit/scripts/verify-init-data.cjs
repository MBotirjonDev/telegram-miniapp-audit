#!/usr/bin/env node
'use strict';
/**
 * Reference implementation of Telegram Mini App initData validation (zero dependencies).
 * Used by the audit to compare a project's implementation against the spec, and
 * handy for developers to copy.
 *
 *   node verify-init-data.cjs --self-test
 *
 * Library use:
 *   const { validateInitData } = require('./verify-init-data.cjs');
 *   const { user, authDate } = validateInitData(rawInitData, process.env.BOT_TOKEN, { maxAgeSeconds: 3600 });
 *
 * Spec: https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app
 *   data_check_string = every field except `hash`, as key=value, sorted by key, joined with \n
 *   secret_key        = HMAC_SHA256(key = "WebAppData", message = bot_token)
 *   hash              = hex(HMAC_SHA256(key = secret_key, message = data_check_string))
 */
const crypto = require('crypto');

class InitDataError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

function dataCheckString(params) {
  return [...params.entries()]
    .filter(([k]) => k !== 'hash')
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');
}

function sign(params, botToken) {
  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  return crypto.createHmac('sha256', secret).update(dataCheckString(params)).digest('hex');
}

function validateInitData(raw, botToken, { maxAgeSeconds = 3600, now = Date.now() } = {}) {
  if (typeof raw !== 'string' || !raw) throw new InitDataError('EMPTY', 'initData is empty');
  if (!botToken) throw new InitDataError('NO_TOKEN', 'bot token is not configured');
  const params = new URLSearchParams(raw);
  const hash = params.get('hash');
  if (!hash || !/^[0-9a-f]{64}$/.test(hash)) throw new InitDataError('NO_HASH', 'hash is missing or malformed');

  const expected = Buffer.from(sign(params, botToken), 'hex');
  const given = Buffer.from(hash, 'hex');
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) {
    throw new InitDataError('BAD_HASH', 'hash does not match');
  }

  const authDate = Number(params.get('auth_date'));
  if (!Number.isInteger(authDate) || authDate <= 0) throw new InitDataError('NO_AUTH_DATE', 'auth_date is missing');
  const age = Math.floor(now / 1000) - authDate;
  if (maxAgeSeconds > 0 && age > maxAgeSeconds) throw new InitDataError('EXPIRED', `initData is ${age}s old`);
  if (age < -60) throw new InitDataError('FUTURE', 'auth_date is in the future');

  let user = null;
  if (params.has('user')) {
    try { user = JSON.parse(params.get('user')); } catch { throw new InitDataError('BAD_USER', 'user is not JSON'); }
    if (!user || !Number.isSafeInteger(user.id)) throw new InitDataError('BAD_USER', 'user.id is missing');
  }
  return { user, authDate, startParam: params.get('start_param'), queryId: params.get('query_id'), params };
}

function selfTest() {
  const assert = require('assert');
  const token = '1000000001:TEST-ONLY-not-a-real-token';
  const now = Date.UTC(2026, 0, 1) ;
  const p = new URLSearchParams({
    query_id: 'AAE-test',
    user: JSON.stringify({ id: 42, first_name: 'Ali', username: 'ali_test' }),
    auth_date: String(Math.floor(now / 1000) - 10),
  });
  p.set('hash', sign(p, token));
  const raw = p.toString();

  assert.strictEqual(validateInitData(raw, token, { now }).user.id, 42);

  const forged = new URLSearchParams(raw);
  forged.set('user', JSON.stringify({ id: 1, first_name: 'Admin' }));
  assert.throws(() => validateInitData(forged.toString(), token, { now }), { code: 'BAD_HASH' });

  assert.throws(() => validateInitData(raw, token, { now: now + 7200 * 1000 }), { code: 'EXPIRED' });
  assert.throws(() => validateInitData(raw, '1000000001:other-token', { now }), { code: 'BAD_HASH' });

  const loginWidgetSecret = crypto.createHash('sha256').update(token).digest();
  const wrong = new URLSearchParams(raw);
  wrong.set('hash', crypto.createHmac('sha256', loginWidgetSecret).update(dataCheckString(wrong)).digest('hex'));
  assert.throws(() => validateInitData(wrong.toString(), token, { now }), { code: 'BAD_HASH' });

  console.log('verify-init-data: self-test passed (valid, forged user, expired, wrong token, Login Widget key)');
}

if (require.main === module) {
  if (process.argv.includes('--self-test')) selfTest();
  else { console.log('Usage: node verify-init-data.cjs --self-test   (or require() it as a library)'); }
}

module.exports = { validateInitData, dataCheckString, sign, InitDataError };
