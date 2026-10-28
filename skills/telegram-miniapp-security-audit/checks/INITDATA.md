# initData and authentication

A Mini App is a web page opened inside Telegram. The page learns who the user is from
`Telegram.WebApp.initData`, a query string **signed with the bot token**. Every request
your backend receives is attacker-controlled until that signature is checked on the
server. This is where most real Mini App breaches happen.

## Checklist

- [ ] The frontend sends the **raw** `Telegram.WebApp.initData` string to the backend
      (header such as `Authorization: tma <initData>`), not fields copied from `initDataUnsafe`
- [ ] Every protected route validates the hash **on the server** before doing anything
- [ ] The secret key is `HMAC_SHA256("WebAppData", bot_token)`, not `SHA256(bot_token)`
- [ ] The hash comparison is constant-time
- [ ] `auth_date` is checked against a maximum age
- [ ] The user id used for authorization comes from the validated `user` field only
- [ ] After validation the server issues its own short-lived session, or re-validates on every request
- [ ] Multi-bot setups validate with the token of the bot that opened the app

## initDataUnsafe is not identity

`Telegram.WebApp.initDataUnsafe` is the same data, parsed, **without any signature**.
It is fine for showing a name in the UI. It is never fine as identity:

```js
// ❌ anyone can send { user_id: 1 } from DevTools or curl
fetch('/api/balance', { body: JSON.stringify({ user_id: tg.initDataUnsafe.user.id }) });

// ✅ send the signed string; the server derives the user
fetch('/api/balance', { headers: { Authorization: `tma ${tg.initData}` } });
```

**Validate:** follow the value. If `initDataUnsafe.user.id` (or `.username`) reaches a
request body, query string, socket message or Firestore/Supabase write, and the server
does not independently validate `initData`, it is a confirmed account-takeover / IDOR.

## The correct algorithm

From the [Telegram Mini Apps docs](https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app):

1. Parse `initData` as a URL query string. Take every field except `hash`.
2. `data_check_string` = the fields as `key=value`, **sorted by key**, joined with `\n`.
   Values are the URL-decoded originals; do not re-encode or re-serialize `user`.
3. `secret_key = HMAC_SHA256(key = "WebAppData", message = bot_token)`
4. `expected = hex(HMAC_SHA256(key = secret_key, message = data_check_string))`
5. Compare `expected` with `hash` in constant time.

Common broken variants:

| Bug | Effect |
|---|---|
| `secret = SHA256(bot_token)` (the **Login Widget** algorithm) | Never validates, so someone "fixes" it by skipping the check |
| HMAC arguments swapped: key = bot_token, message = "WebAppData" | Never validates |
| Re-serializing `user` with `JSON.stringify` before signing | Never validates for some names |
| Sorting `key=value` strings instead of keys | Breaks on keys that are prefixes of others |
| Validation wrapped in `try { … } catch { return true }` or only in production | Bypass |
| Check exists but a route forgot the middleware | Bypass on that route |

Use a maintained library where possible: `@telegram-apps/init-data-node` (Node),
`aiogram.utils.web_app.safe_parse_webapp_init_data` (Python), or the reference
implementation in `scripts/verify-init-data.cjs`.

Newer clients also include a `signature` field (Ed25519) that lets **third parties**
verify initData with Telegram's public key, without the bot token. If the project uses
it, check that it verifies against the right bot id and the production key.

## Validate auth_date

A signed initData string never stops being valid on its own. It ends up in logs, proxies,
crash reports and screenshots. Reject it after a window that matches the app:

```js
if (Date.now() / 1000 - Number(params.get('auth_date')) > 3600) throw new Error('expired');
```

**Severity:** medium when initData is logged or stored anywhere (see `BACKEND.md#logging`),
low otherwise.

## Never trust ids from the client

After validation, the only trustworthy identity is `user.id` from the validated string.
Request fields such as `user_id`, `telegram_id`, `chat_id` are attacker-controlled:

```python
# ❌
user_id = request.json["user_id"]
# ✅
user_id = validated_init_data.user.id
```

**Validate:** is the request id used to read or modify data that belongs to someone else
(balance, orders, referrals, profile)? Is there an ownership check against the validated
id? An admin endpoint that accepts `user_id` to act on others is fine only if the caller's
validated id is in a server-side admin list.

## Compare in constant time

| Language | Use |
|---|---|
| Node | `crypto.timingSafeEqual(a, b)` after checking equal length |
| Python | `hmac.compare_digest(a, b)` |
| PHP | `hash_equals($expected, $given)` |
| Go | `hmac.Equal(a, b)` |

On its own this is a **low** hardening note; practical timing attacks over the internet
are hard. Report it together with the other initData findings, not as a headline.
