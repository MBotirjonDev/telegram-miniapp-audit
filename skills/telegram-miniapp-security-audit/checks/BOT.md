# The bot

The bot token is the master key of the whole product: it reads updates, sends as the bot,
sets the webhook, creates invoices, and is the HMAC key for every Mini App session.

## Checklist

- [ ] The token is only in server-side environment/secret storage, never in git, the
      frontend bundle, mobile apps or client-side env vars
- [ ] Git history is clean (`git log -p -S ':AA' --all` style search) or the token was revoked
- [ ] The webhook uses `secret_token`, and the handler rejects requests without the header
- [ ] The webhook URL path is not guessable on its own (defence in depth, not a replacement)
- [ ] Admin commands check numeric `from_user.id` against a server-side list
- [ ] User-supplied text is escaped before being sent with `parse_mode=HTML`/`MarkdownV2`
- [ ] Group bots check that the chat and the sender are what the command expects
- [ ] Long polling and webhook are not both running against the same token

## Bot token

Format: `<bot id>:<35 chars>`, usually starting with `AA` after the colon.

Impact if leaked: read new messages and files sent to the bot, message every user who
started it (phishing as your brand), change the webhook to steal all future updates,
**forge valid initData for any user** and so log in to the Mini App backend as anyone,
issue invoices in your name.

Fix: `@BotFather → /revoke`, update the server secret, then purge history (or treat it as
public forever). Rotation also invalidates every outstanding initData signature.

### Client-side env vars

Bundlers inline variables with these prefixes into the JavaScript that every user
downloads: `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `NUXT_PUBLIC_`, `PUBLIC_`, `EXPO_PUBLIC_`.
`VITE_BOT_TOKEN` is a published token. Same for `--dart-define` in a Flutter Web Mini App.

## Bot API from the client

Any call to `https://api.telegram.org/bot<token>/…` from the Mini App means the token is
in the browser. Typical reason: "send the user a confirmation message". The fix is a
backend endpoint that validates initData and sends the message itself. If the app has no
backend, `Telegram.WebApp.sendData()` (keyboard-button Mini Apps) or `answerWebAppQuery`
on the server are the supported paths.

## Webhook secret

`setWebhook` accepts `secret_token` (1–256 chars, `A-Z a-z 0-9 _ -`). Telegram then sends it
in every request as `X-Telegram-Bot-Api-Secret-Token`.

```python
await bot.set_webhook(url, secret_token=os.environ["WEBHOOK_SECRET"])
# aiogram's SimpleRequestHandler(dispatcher, bot, secret_token=...) checks the header
```

```js
// grammY
app.use(webhookCallback(bot, 'express', { secretToken: process.env.WEBHOOK_SECRET }));
```

Without it, anyone who learns the URL (logs, a reverse proxy, a past screenshot) can POST
forged updates: messages "from" an admin id, fake `successful_payment` updates, fake
`web_app_data`. **Validate** what a forged update can do: if the bot grants anything on
`successful_payment` or trusts `from.id` for admin commands, the missing secret is high.

## Admins by numeric id

Usernames can be changed, released, and then claimed by someone else. A deleted account's
username becomes available. Compare `from_user.id` (an integer that never changes) against
a list stored on the server (env var, database), never against a username or display name.

## HTML injection in messages

`first_name`, `last_name`, `username`, message text and captions are attacker-controlled.
With `parse_mode="HTML"`, a name like `</b><a href="https://evil.example">Verify</a>`
turns the bot's own message into a phishing link, or makes sending fail (a DoS for that
user's flow).

```python
from aiogram import html
await message.answer(f"Salom, <b>{html.quote(message.from_user.first_name)}</b>!", parse_mode="HTML")
```

Telegram only renders a small tag set, so this is **content injection, not script
execution**. Low by default; medium when the bot broadcasts user-controlled text to other
users or admins (reviews, orders, support tickets).
