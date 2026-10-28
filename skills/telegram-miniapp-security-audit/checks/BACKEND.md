# The Mini App backend

Most Mini App backends are small (Express, FastAPI, Laravel, Supabase Edge Functions,
Firebase) and were written fast. Assume every route is reachable with `curl`.

## Checklist

- [ ] One auth middleware validates initData (see `INITDATA.md`) and is applied to **every** route
- [ ] Every object lookup checks ownership against the validated user id (orders, balances, referrals)
- [ ] Balance and credit changes happen in a transaction, with a unique constraint against double-spend
- [ ] Referral and bonus logic cannot be farmed: one reward per referred user, no self-referral,
      no reward for accounts created minutes ago if that matters for the business
- [ ] Rate limits on login-like and reward endpoints (per validated user id, not per IP only)
- [ ] CORS limited to the Mini App origin
- [ ] Logs never contain initData, bot tokens or webhook secrets
- [ ] Firebase / Supabase: rules or RLS enforce the same ownership checks (clients can call them directly)

## IDOR

The usual pattern: `GET /api/orders/:id` checks that the caller is *a* valid Telegram
user, but not that the order belongs to them. Validate by reading the query: is there
`WHERE user_id = <validated id>` (or an RLS policy using it)? If not, confirmed.

## Games, tap-to-earn and points

Anything the client reports ("I tapped 5000 times", "I finished level 9", "I watched the
ad") is attacker-controlled. Look for score, energy or reward values accepted from the
request body without server-side limits or server-side simulation. Severity depends on
whether points convert to money, tokens or prizes.

## CORS

`cors()` with no options, `origin: '*'`, `origin: true` or `allow_origins=["*"]` lets any
website call the API from a victim's browser. If auth is an explicit `Authorization: tma …`
header that only the Mini App has, a wildcard is mostly harmless (**low**). If the API uses
cookies or reflects the origin **with credentials**, it is a real cross-site request issue
(**medium/high**). Allow only your Mini App domain(s).

## Logging

initData in logs can be replayed until `auth_date` expires (forever, if it is not
checked). A bot token or webhook secret in logs is a full compromise for anyone with log
access (hosting dashboard, error tracker, a teammate). Log the validated `user.id` and a
request id instead, and configure the logger/Sentry to scrub `authorization` and
`x-init-data` headers.
