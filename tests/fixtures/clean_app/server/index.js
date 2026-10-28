// Reference Mini App backend: identity only from validated initData.
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors({ origin: ['https://miniapp.example.uz'] }));
app.use(express.json());

const MAX_AGE_SECONDS = 3600;

function validateInitData(raw) {
  const params = new URLSearchParams(raw || '');
  const received = Buffer.from(params.get('hash') || '', 'hex');
  params.delete('hash');
  const dataCheck = [...params.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(process.env.BOT_TOKEN).digest();
  const expected = crypto.createHmac('sha256', secret).update(dataCheck).digest();
  if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) return null;
  const authDate = Number(params.get('auth_date'));
  if (!authDate || Date.now() / 1000 - authDate > MAX_AGE_SECONDS) return null;
  return { user: JSON.parse(params.get('user')) };
}

function requireTelegram(req, res, next) {
  const [scheme, raw] = (req.headers.authorization || '').split(' ');
  const auth = scheme === 'tma' ? validateInitData(raw) : null;
  if (!auth) return res.sendStatus(401);
  req.telegramUser = auth.user;
  return next();
}

app.post('/api/me', requireTelegram, (req, res) => {
  res.json({ id: req.telegramUser.id, firstName: req.telegramUser.first_name });
});

app.listen(3000);
