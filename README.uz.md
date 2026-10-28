# Telegram Mini App Audit 🇺🇿

**Claude Code, Codex yoki Cursor'ni Telegram bot va Mini App xavfsizlik auditoriga aylantiradi.**

Bu agent skill Telegram botlari, Mini App'lar va ularning backend'ini hujumchi ko'zi bilan
tekshiradi. Yonida bog'liqliksiz (zero-dependency) skaner ham bor: kompyuterda ham, CI'da
ham ishlaydi.

[English README](README.md)

## Nega kerak

Mini App'lar odatda tez yoziladi va bir xil joylarda xato qiladi:

- backend **`initDataUnsafe.user.id`** yoki so'rovdagi `user_id`'ga ishonadi: istalgan odam boshqa foydalanuvchi nomidan ish qila oladi
- initData **Login Widget** algoritmi bilan tekshiriladi, tekshiruv hech qachon o'tmaydi va oxiri o'chirib qo'yiladi
- **bot token** git'da, `VITE_` o'zgaruvchisida yoki frontend'dagi `api.telegram.org/bot…` so'rovida turadi
- **webhook'da `secret_token` yo'q**: istalgan odam soxta update va soxta to'lov yubora oladi
- premium `openInvoice` callback'i `paid` deganda ochiladi, `successful_payment`'da emas
- adminlar **username** bo'yicha tekshiriladi

## Tez boshlash

Skill sifatida:

```bash
npx skills add https://github.com/MBotirjonDev/telegram-miniapp-audit --skill telegram-miniapp-security-audit --global
```

So'ng loyihangizda agentga yozing:

```
security audit this telegram mini app
```

Faqat skaner (Node 18+, `npm install` kerak emas):

```bash
node skills/telegram-miniapp-security-audit/scripts/scan.cjs path/to/project
```

initData'ni to'g'ri tekshirish uchun tayyor kod: `scripts/verify-init-data.cjs`
(`--self-test` bilan sinab ko'ring).

## Qanday ishlaydi

1. **Razvedka:** aktivlar, kirish nuqtalari, identifikatsiya qanday qilinishi, pul qayerda harakatlanishi
2. **Triage:** skaner natijalari savol sifatida qabul qilinadi, javob emas
3. **Ov:** har bir soha uchun checklist (`checks/*.md`)
4. **Tekshiruv:** alohida "verifier" har bir topilmani rad etishga urinadi
5. **Natija:** `findings.json` va tuzatish kodi bilan `REPORT.md`

## Hissa qo'shish

Yangi qoida = regex + fixture + test. Batafsil: [CONTRIBUTING.md](CONTRIBUTING.md).

MIT litsenziyasi. Telegram bilan bog'liq emas.
