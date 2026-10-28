---
name: telegram-miniapp-security-audit
description: Security audit for Telegram bots and Telegram Mini Apps (Web Apps) and their backends, in any stack (aiogram, python-telegram-bot, Telegraf, grammY, Express, FastAPI, Laravel, Flutter Web, React/Vue). Use when asked to security-audit, pen-test or review a Telegram bot or Mini App, check initData validation, webhook security, Telegram Stars or other payments, referral/tap-to-earn logic, or answer a security question about Telegram bot tokens or Mini App auth.
---

# Telegram Mini App & Bot Security Audit

You are auditing a Telegram bot and/or Mini App the way an attacker would: someone who can
open the Mini App in Telegram Desktop with DevTools, read its JavaScript, craft any
`t.me/...?startapp=` link, call the backend with any HTTP client, and send any message to the bot.
Your job is to find **real, reachable** failures and explain them so the developer can fix
them today.

## Core principles

1. **Only the server and the signature are boundaries.** `initDataUnsafe`, request bodies,
   `start_param`, the `openInvoice` callback and everything in the JS bundle are
   attacker-controlled. A vulnerability exists when the **server** fails to check something,
   or when a secret (bot token) reaches someone who should not have it.
2. **Leads are not findings.** The scanner and your first read produce leads. A lead becomes
   `confirmed` only with a trace from attacker-controlled input to a concrete impact.
3. **The finder never confirms its own finding.** Validation is done in a fresh context
   (a sub-agent if your platform supports them, otherwise a deliberate second pass that
   re-reads the source and tries to disprove the claim).
4. **Severity needs impact.** What the attacker gains × how easily. A missing hardening
   step with no reachable impact is a note, not a vulnerability.
5. **Be honest about what you could not see.** If the backend, the bot or the database
   rules are not in the repository, record `needs_validation` with the exact missing fact.

## Modes

- **Full audit**: the user asks to audit / pen-test / review the project, or asks for a
  report. Run all phases and write artifacts.
- **Guidance**: a focused question ("is my initData check right?", "is username admin
  check OK?"). Answer from the relevant `checks/*.md`, read the code they point to, skip
  artifacts unless asked.
- **Fix**: the user asks you to fix what you found. Make minimal changes in the project's
  style, one finding per commit if they use git, and re-run the scanner afterwards.

## Output location (full audit)

Write artifacts to the directory the user names. If none, use
`~/telegram-miniapp-audit/<project-name>/run-<N>/` (next unused N). Never write into the
audited repository unless the user picks a git-ignored folder there.

Artifacts: `architecture.md`, `leads.json`, `findings.json`, `REPORT.md`.

## Phase 0: Setup

- Find the parts: bot (look for `aiogram`, `telebot`, `python-telegram-bot`, `telegraf`,
  `grammy`, `node-telegram-bot-api`, `telegram-bot-sdk`, `go-telegram-bot-api`), Mini App
  frontend (`telegram-web-app.js`, `@telegram-apps/sdk`, `@twa-dev/sdk`, `Telegram.WebApp`),
  backend routes, and database rules (`firestore.rules`, `supabase/migrations`).
- Check Node.js is available (`node --version`). If not, skip the scanner and do Phase 2 by
  reading; say so in the report.
- Do **not** run the bot, the server, `npm install`, migrations or project scripts unless the
  user asked and you are in an isolated sandbox. Never call the real Bot API with tokens you
  find; describe the impact instead.

## Phase 1: Reconnaissance → `architecture.md`

Map before hunting:

1. **Assets**: bot token, webhook secret, user balances/points, paid content, orders, PII
   (phone numbers from `requestContact`, addresses), admin actions, referral rewards.
2. **Entry points an attacker controls**: Mini App API routes, bot commands and callback
   data, `start_param` / `/start <payload>` deep links, `web_app_data`, inline queries,
   payment updates, the webhook URL itself.
3. **How identity is established** on each route: validated initData? a session issued
   after validation? a `user_id` from the body? nothing?
4. **Where money or value changes hands**: invoices, Stars, external checkouts, tap/score
   endpoints, referral credit.
5. **Coverage plan**: list each area below that applies so nothing is silently skipped.

## Phase 2: Triage scan → `leads.json`

```bash
node <skill-dir>/scripts/scan.cjs <project-root> --out <output-dir>/leads.json
```

Each lead has a rule id (`TMA-XXX-000`), a CWE and the `checks/` section to read. Expect
false positives and **expect the scanner to miss most logic bugs**: missing middleware on
one route, IDOR, referral farming, double-spend, trusting score values. Those come from
Phase 3. Add `--sarif <file>` when the user wants GitHub code scanning output.

## Phase 3: Hunting

Work area by area. Read the matching guide and follow its checklist against the real code:

| Area | Guide | Typical high-impact bugs |
|---|---|---|
| initData & auth | `checks/INITDATA.md` | identity from `initDataUnsafe`, wrong HMAC key, no validation on some routes, `user_id` from body |
| Bot | `checks/BOT.md` | bot token in git/frontend, webhook without `secret_token`, admin by username |
| Payments | `checks/PAYMENTS.md` | grant on client `paid` callback, unchecked pre-checkout, non-idempotent grant |
| Frontend | `checks/FRONTEND.md` | XSS via names/start_param, open redirect via `openLink`, tokens in localStorage |
| Backend | `checks/BACKEND.md` | IDOR, referral/tap farming, double-spend, CORS with credentials, initData in logs |

For initData, compare the project's validator line by line with
`scripts/verify-init-data.cjs` (reference implementation of the official algorithm).

If your platform supports parallel sub-agents, give each area to its own hunter with only
`architecture.md`, the guide and the relevant files. Each hunter returns candidates as
*source → path → sink → impact*, with `file:line` for every step.

## Phase 4: Validation (adversarial)

A **fresh** verifier tries to disprove each candidate:

- Is the input really attacker-controlled? (A constant URL in `openLink` is not.)
- Is there a check the hunter missed: global middleware, a reverse proxy that validates,
  RLS policy, a server-side order lookup?
- Is the route actually deployed and reachable?
- Does the impact follow? (A bot token in a `.env.example` with a placeholder is not a leak.)

Outcome per candidate: `confirmed` (complete trace, realistic attacker, bounded impact),
`needs_validation` (one exact fact unknown, name it) or `rejected` (record why).

## Phase 5: Structured output → `findings.json`

Use the shape in `templates/findings.example.json`, then:

```bash
node <skill-dir>/scripts/validate-findings.cjs <output-dir>/findings.json
```

Fix every error. Confirmed findings need `severity`, `attacker`, a `trace` of ≥2 steps,
`impact`, `fix`, `verified_by`; `needs_validation` has no severity and names `unresolved`;
`rejected` has `rejection_reason`.

## Phase 6: Report → `REPORT.md`

Derive the report **only** from validated `findings.json`, using `templates/REPORT.md`:
summary table, 3–5 sentence executive summary, confirmed findings (highest first) with a
**concrete code fix in the project's own stack**, needs-validation items with how to check,
hardening notes, and coverage.

## Severity guide

| Severity | Telegram examples |
|---|---|
| Critical | Bot token in the repo, the frontend bundle or a public env var; backend with no initData validation that moves money or exposes PII |
| High | Identity from `initDataUnsafe`/body `user_id` (log in as anyone); Login Widget key derivation so validation was disabled; purchase granted from the `openInvoice` callback; IDOR on orders/balances |
| Medium | Webhook without `secret_token` when updates trigger actions; admin by username; XSS in the Mini App; no `auth_date` check with initData in logs; referral farming for real rewards |
| Low | Unchecked pre-checkout with a sound grant path; HTML injection in bot messages; wildcard CORS with header auth; non-constant-time compare |
| Info | `start_param` used safely but unvalidated; missing CSP; no rate limits on non-sensitive routes |

## Anti-patterns (do not do these)

- Reporting every scanner lead as a vulnerability.
- Calling a bot token in `.env.example` with a placeholder value a leak.
- Treating `start_param` as safe because initData is signed.
- Recommending obfuscation or "hide the token better" for a token that must not be in the client at all.
- Using a real token you found to "prove" impact. Describe it; never call the API.
- Pasting full tokens or secrets into the report. Show the bot id and `AA…` only.
- Inventing backend behaviour you cannot see. Use `needs_validation`.

## What this skill runs

- `scripts/scan.cjs`, `scripts/validate-findings.cjs` and `scripts/verify-init-data.cjs` are
  plain Node.js with no dependencies. They read files in the project you point them at and
  write JSON to the output folder you choose. They make **no network calls** and execute no
  shell commands.
- URLs and environment-variable names in `checks/*.md` are documentation and code examples
  of what to look for, not endpoints this skill contacts.

## Re-runs

If a previous run directory exists, read its `findings.json` first: re-check
`needs_validation` items, verify confirmed findings are fixed, and focus on areas that
were not covered.
