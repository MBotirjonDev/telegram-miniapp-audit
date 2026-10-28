# Contributing

Thanks for helping Telegram bots and Mini Apps ship safer. A new rule, a false-positive
fix, a better checklist item and a translation all count.

## Add a scanner rule (≈15 minutes)

1. **Open an issue first** with the *New rule* template, so nobody duplicates work.
2. Add the rule to `skills/telegram-miniapp-security-audit/scripts/rules.cjs`:
   - next free id in the area: `TMA-<AREA>-<NNN>` (`SEC AUTH BOT PAY WEB NET STO CRY LOG`)
   - `files`, `pattern` (with the `g` flag), `severity`, `cwe`, `guide`, `message`, `fix`
   - keep false positives low with `exclude`, `nearbyExclude`, `fileRequires` / `fileAbsent`
   - use `helpers.isFrontend` / `helpers.isServer` when the bug only matters on one side
3. Add a **positive case** to `tests/fixtures/vuln_app/`. Anything that looks like a real
   token must be generated in `tests/scan.test.cjs` instead (GitHub push protection).
4. Keep `tests/fixtures/clean_app/` clean; add a tricky **negative** case there if your
   rule could misfire.
5. Add or extend the section in `skills/telegram-miniapp-security-audit/checks/*.md`
   (the `guide` anchor must exist; the tests check it).
6. Update the rules table in `README.md`.
7. `npm test`: all green, no new dependencies.

Please also run your rule against a couple of real open-source bots or Mini Apps and
mention the false-positive count in the PR.

## Ground rules

- Zero runtime dependencies. Node ≥ 18 standard library only.
- Rules produce **leads**; wording says "review"/"may", not "you are hacked".
- Never include real tokens, real company names or real users in fixtures or docs.
- Found a vulnerability *in this project*? See [SECURITY.md](SECURITY.md).
- Be kind in reviews. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
