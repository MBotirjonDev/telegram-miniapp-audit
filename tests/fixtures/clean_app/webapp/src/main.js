// Reference Mini App frontend: sends raw initData, renders with textContent.
const tg = window.Telegram.WebApp;
tg.ready();

async function api(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `tma ${tg.initData}` },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

const me = await api('/api/me');
document.getElementById('hello').textContent = `Salom, ${me.firstName}`;

export function buyPremium(link) {
  // The server grants premium on successful_payment; the callback only refreshes the UI.
  tg.openInvoice(link, () => api('/api/me'));
}
