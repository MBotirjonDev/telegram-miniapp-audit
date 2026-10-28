# Security audit: {{project}}

| | |
|---|---|
| Commit | `{{commit}}` |
| Date | {{date}} |
| Scope | {{bot / Mini App frontend / backend / database rules audited}} |
| Method | telegram-miniapp-security-audit skill: recon → triage scan → hunting → adversarial validation |

## Summary

| Critical | High | Medium | Low | Needs validation |
|---:|---:|---:|---:|---:|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

{{3–5 sentences: what the bot/Mini App does, the most serious problem in plain words, what to fix first.}}

## Confirmed findings

### F-1 · {{title}} (**{{Severity}}**)

**Where:** `{{file}}:{{line}}` · **CWE:** {{cwe}}

**Attacker:** {{who, and what they control}}

**How it works**
1. {{step with file:line}}
2. {{step with file:line}}
3. {{impact}}

**Impact:** {{what is lost or gained, in business terms}}

**Fix**
```js
// before → after, in the project's own stack
```

---

## Needs validation

| ID | Title | What to check |
|---|---|---|
| F-n | {{title}} | {{exact unresolved fact and how to verify it}} |

## Hardening notes

- {{no direct impact, but worth doing}}

## Coverage

| Area | Status | Notes |
|---|---|---|
| initData & auth | ✅ audited | |
| Bot (token, webhook, admins, messages) | ✅ audited | |
| Payments | ✅ audited | |
| Mini App frontend | ✅ audited | |
| Backend (IDOR, rewards, CORS, logs) | ⚠️ partial | {{e.g. database rules not in repo}} |

_Generated with [Telegram Mini App Audit](https://github.com/MBotirjonDev/telegram-miniapp-audit). Automated audits miss things; repeat runs and a human review increase coverage._
