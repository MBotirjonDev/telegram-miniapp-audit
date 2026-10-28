// Intentionally vulnerable Mini App backend used by the test suite. Do not copy.
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

function checkInitData(initData) {
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  params.delete('hash');
  const dataCheck = [...params.entries()].sort().map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(process.env.BOT_TOKEN).digest();
  const calculatedHash = crypto.createHmac('sha256', secret).update(dataCheck).digest('hex');
  return calculatedHash === hash;
}

app.post('/api/balance', (req, res) => {
  if (!checkInitData(req.headers['x-init-data'])) return res.sendStatus(401);
  const userId = req.body.user_id;
  res.json({ userId, balance: 1000 });
});

app.listen(3000);
