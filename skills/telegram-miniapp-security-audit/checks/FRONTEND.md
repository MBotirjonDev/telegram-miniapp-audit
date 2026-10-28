# The Mini App frontend

The frontend is an ordinary web page with one extra superpower: it holds the user's
signed `initData`. Any script that runs on the page can call your API as that user.

## Checklist

- [ ] No HTML sinks fed with user, API or link data (`innerHTML`, `v-html`, `dangerouslySetInnerHTML`, `{@html}`)
- [ ] `start_param` / `tgWebAppStartParam` is validated against a strict format
- [ ] Navigation (`location`, `window.open`, `openLink`, `openTelegramLink`) only to allow-listed https URLs
- [ ] No tokens, sessions or initData in `localStorage`
- [ ] No secrets in the bundle (see `BOT.md#client-side-env-vars`)
- [ ] Content-Security-Policy restricts scripts to your origin plus `telegram.org`
- [ ] The app still behaves when opened in a normal browser outside Telegram (no initData): it must fail closed
- [ ] Third-party scripts (analytics, chat widgets) are few and pinned

## XSS in a Mini App

Impact is larger than on a normal site: the payload runs with the victim's initData, so it
can call every API route as them (transfer balance, place orders, read profile), and can
use `Telegram.WebApp` methods (send data to the bot, open links, request phone number
prompts) in the trusted Telegram UI.

**Validate:** find what flows into the sink. Sources that count: `start_param`, URL query
and hash, API fields written by other users (names, reviews, chat messages, product
descriptions), and `initDataUnsafe.user` fields (users choose their own names).
A static string or sanitized markup (DOMPurify) is not a finding.

## start_param is attacker-controlled

`https://t.me/<bot>/<app>?startapp=<value>` lets anyone choose `start_param`. It arrives in
the signed initData, but the signature only proves Telegram delivered it, not that **you**
created the link. Treat it like a query string:

- never as HTML, a URL, a file path, or part of SQL
- never as an authorization decision ("startapp=admin")
- for referrals: validate format, forbid self-referral (`referrer == user.id`), and
  credit once per referred user on the server

## Open redirects and openLink

`location.href = value` and `window.open(value)` with an unvalidated value is an open
redirect, and with `javascript:` URLs, XSS. `Telegram.WebApp.openLink(value)` opens an
external browser with your Mini App's credibility; `openTelegramLink` can open any bot or
channel. Allow-list hosts:

```js
const u = new URL(value, location.origin);
if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) return;
tg.openLink(u.href);
```

## Storage

`localStorage` is shared by every script on the origin and survives logout. Prefer to keep
the session in memory and re-authenticate with `initData` on every launch (it is always
available inside Telegram). Telegram's `CloudStorage` is synced to the user's Telegram
account and readable by your bot: do not put secrets there. For device-bound secrets,
newer clients offer `SecureStorage`; check availability before relying on it.
