// Intentionally vulnerable Mini App frontend used by the test suite. Do not copy.
const tg = window.Telegram.WebApp;
const user = tg.initDataUnsafe.user;

document.getElementById('hello').innerHTML = 'Salom, ' + user.first_name;

fetch('/api/balance', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-init-data': tg.initData },
  body: JSON.stringify({ user_id: user.id }),
});

fetch(`https://api.telegram.org/bot${import.meta.env.VITE_BOT_TOKEN}/sendMessage`, {
  method: 'POST',
  body: JSON.stringify({ chat_id: user.id, text: 'opened the app' }),
});

const promo = tg.initDataUnsafe.start_param;
if (promo) window.location.href = promo;

export function saveSession(token) {
  localStorage.setItem('session_token', token);
}

export function buyPremium(link) {
  tg.openInvoice(link, (status) => {
    if (status === 'paid') unlockPremium();
  });
}
