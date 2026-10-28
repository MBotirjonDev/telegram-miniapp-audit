'use strict';
/**
 * Triage rules for telegram-miniapp-security-audit.
 *
 * Every hit is a LEAD, not a finding. The skill workflow requires an agent
 * (or a human) to trace each lead before it becomes a confirmed finding.
 *
 * Rule fields:
 *   id           TMA-<AREA>-<NNN>   AREA: SEC AUTH BOT PAY WEB NET STO CRY LOG
 *   files        RegExp tested against the path (forward slashes), or a function(path) → bool
 *   pattern      RegExp with the `g` flag; each match is one lead
 *   exclude      optional RegExp; drop the lead if the file PATH or the matched LINE matches
 *   fileRequires optional RegExp; the rule only runs on files whose full text matches it
 *   nearbyExclude optional { pattern, before }; drop the lead if one of the `before` lines
 *                above the match matches `pattern` (e.g. a check that guards it)
 *   fileAbsent   optional RegExp; the rule only runs on files whose full text does NOT match it
 *                (file-level rules report the first `pattern` match only)
 *   severity     critical | high | medium | low | info   (triage guess only)
 *   cwe          CWE id the rule maps to
 *   guide        checks/<FILE>.md#anchor the agent reads to validate the lead
 *
 * Every rule needs a positive case in tests/fixtures/vuln_app, and
 * tests/fixtures/clean_app must stay clean.  `npm test` enforces both.
 */

const JS = /\.(m?js|cjs|jsx|ts|tsx|vue|svelte|astro)$/;
const PY = /\.py$/;
const PHP = /\.php$/;
const GO = /\.go$/;
const DART = /\.dart$/;
const CODE = /\.(m?js|cjs|jsx|ts|tsx|vue|svelte|astro|py|php|go|dart|rb|java|kt|cs)$/;
const SERVER_CODE = /\.(m?js|cjs|ts|py|php|go|rb|java|kt|cs)$/;
const CONFIG = /(^|\/)\.env(\.[\w-]+)?$|\.(ya?ml|json|toml|ini|properties)$/;
const ANY_TEXT = (p) => CODE.test(p) || CONFIG.test(p) || /\.(html?|sh)$/.test(p);

// Heuristic split between code that ships to the user's browser (the Mini App)
// and code that runs on a server or inside the bot process.
const SERVER_DIR = /(^|\/)(server|backend|api|bot|bots|functions|supabase|worker|workers|handlers|webhook|webhooks|cmd|internal)\//;
const FRONT_DIR = /(^|\/)(src|public|web|webapp|web_app|miniapp|mini-app|mini_app|client|frontend|app|pages|components|static|assets|lib)\//;
const FRONT_FILE = /\.(m?js|jsx|ts|tsx|vue|svelte|astro|html?|dart)$/;
const isFrontend = (p) => FRONT_FILE.test(p) && FRONT_DIR.test(p) && !SERVER_DIR.test(p) && !/(^|\/)(server|api|bot|webhook)\.(m?js|ts)$/.test(p);
const isServer = (p) => SERVER_CODE.test(p) && !isFrontend(p);


module.exports = [
  // ---------------------------------------------------------------- secrets
  {
    id: 'TMA-SEC-001',
    title: 'Telegram bot token in source',
    severity: 'critical',
    files: ANY_TEXT,
    pattern: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g,
    cwe: 'CWE-798',
    guide: 'BOT.md#bot-token',
    message: 'A bot token gives full control of the bot: read every message sent to it, message every user, change the webhook, and forge valid Mini App initData.',
    fix: 'Revoke it with @BotFather (/revoke), load the new token from the server environment, and purge it from git history.',
  },
  {
    id: 'TMA-SEC-002',
    title: 'Bot token exposed to the Mini App frontend',
    severity: 'critical',
    files: ANY_TEXT,
    pattern: /\b(VITE|NEXT_PUBLIC|REACT_APP|NUXT_PUBLIC|PUBLIC|EXPO_PUBLIC)_\w*(BOT_TOKEN|TG_TOKEN|TELEGRAM_TOKEN|BOT_API_TOKEN)\w*/g,
    cwe: 'CWE-200',
    guide: 'BOT.md#bot-token',
    message: 'Variables with this prefix are inlined into the browser bundle. Anyone who opens the Mini App can read the bot token from DevTools.',
    fix: 'Rename it without the public prefix, read it only on the server, and revoke the exposed token with @BotFather.',
  },
  {
    id: 'TMA-SEC-003',
    title: 'Telegram Bot API called from the frontend',
    severity: 'high',
    files: isFrontend,
    pattern: /api\.telegram\.org\/bot/g,
    cwe: 'CWE-602',
    guide: 'BOT.md#bot-api-from-the-client',
    message: 'Calling the Bot API from the Mini App means the bot token is in the browser.',
    fix: 'Move Bot API calls to your backend. The Mini App calls your API with initData; the server validates it and talks to Telegram.',
  },

  // ---------------------------------------------------------------- initData / auth
  {
    id: 'TMA-AUTH-001',
    title: 'Identity taken from initDataUnsafe',
    severity: 'medium',
    files: (p) => JS.test(p) || DART.test(p) || /\.html?$/.test(p),
    pattern: /initDataUnsafe\s*(\?\.|\.)\s*user/g,
    cwe: 'CWE-290',
    guide: 'INITDATA.md#initdataunsafe-is-not-identity',
    message: 'initDataUnsafe is unsigned. If this user id is sent to the backend as identity, anyone can call your API as any Telegram user.',
    fix: 'Send the raw Telegram.WebApp.initData string (e.g. `Authorization: tma <initData>`) and derive the user on the server after validating the hash.',
  },
  {
    id: 'TMA-AUTH-002',
    title: 'Backend trusts a user id from the request',
    severity: 'medium',
    files: isServer,
    pattern: /\b(req\.(body|query|params)|request\.(json|args|form|GET|POST|query_params|data)|ctx\.request\.body|\$_(GET|POST|REQUEST)|c\.(Query|PostForm|Param))\s*(\??\.)?\s*[\[(]?\s*['"]?(user_?id|userId|telegram_?id|telegramId|tg_?id|tgId|chat_?id|chatId)\b/g,
    cwe: 'CWE-639',
    guide: 'INITDATA.md#never-trust-ids-from-the-client',
    message: 'A Telegram user id read from the request body/query can be changed by the caller. This is the classic Mini App IDOR.',
    fix: 'Take the user id from validated initData (server side) and ignore ids sent by the client.',
  },
  {
    id: 'TMA-AUTH-003',
    title: 'initData validated without an auth_date freshness check',
    severity: 'medium',
    files: SERVER_CODE,
    fileRequires: /^(?=[\s\S]*(?:\bb)?['"`]WebAppData['"`])(?=[\s\S]*(hmac|Hmac|HMAC))/,
    fileAbsent: /auth_date|authDate|expiresIn|expires_in|max_age|maxAge/,
    pattern: /(?:\bb)?['"`]WebAppData['"`]/g,
    cwe: 'CWE-294',
    guide: 'INITDATA.md#validate-auth_date',
    message: 'A correctly signed initData string stays valid forever unless auth_date is checked. A leaked or logged string can be replayed.',
    fix: 'Reject initData whose auth_date is older than your session window (for example 1 hour), then issue your own short-lived session.',
  },
  {
    id: 'TMA-AUTH-004',
    title: 'Login Widget key derivation used for Mini App initData',
    severity: 'high',
    files: SERVER_CODE,
    fileRequires: /initData|init_data|tgWebAppData|WebApp/,
    fileAbsent: /WebAppData/,
    pattern: /createHash\(\s*['"]sha256['"]\s*\)\s*\.update\(\s*[\w.]*(token|TOKEN)|hashlib\.sha256\(\s*[\w.]*(token|TOKEN)|hash\(\s*['"]sha256['"]\s*,\s*\$\w*(token|TOKEN)|sha256\.Sum256\(\s*\[\]byte\(\s*\w*(token|Token|TOKEN)/g,
    cwe: 'CWE-347',
    guide: 'INITDATA.md#the-correct-algorithm',
    message: 'SHA256(bot_token) is the Login Widget secret. Mini App initData uses HMAC_SHA256("WebAppData", bot_token). The check either always fails or was "fixed" by weakening it.',
    fix: 'secret_key = HMAC_SHA256(key="WebAppData", msg=bot_token); expected = hex(HMAC_SHA256(key=secret_key, msg=data_check_string)). Use a maintained library such as @telegram-apps/init-data-node or aiogram.utils.web_app.',
  },
  {
    id: 'TMA-CRY-001',
    title: 'Signature compared with a non-constant-time operator',
    severity: 'low',
    files: SERVER_CODE,
    fileRequires: /WebAppData|initData|init_data|secret_token|secretToken/,
    pattern: /\b\w*(hash|Hash|HASH|signature|Signature|digest|Digest)\w*\s*(!==|===|!=|==)\s*\w*(hash|Hash|HASH|signature|Signature|digest|Digest)\w*/g,
    cwe: 'CWE-208',
    guide: 'INITDATA.md#compare-in-constant-time',
    message: 'String equality leaks timing. Low risk on its own, but it is the cheap part to get right.',
    fix: 'Node: crypto.timingSafeEqual(Buffer.from(a,"hex"), Buffer.from(b,"hex")). Python: hmac.compare_digest. PHP: hash_equals. Go: hmac.Equal.',
  },

  // ---------------------------------------------------------------- bot
  {
    id: 'TMA-NET-001',
    title: 'Webhook set without a secret token',
    severity: 'medium',
    files: SERVER_CODE,
    fileAbsent: /secret_token|secretToken|X-Telegram-Bot-Api-Secret-Token|x-telegram-bot-api-secret-token|SecretToken/,
    pattern: /\b(setWebhook|set_webhook|setWebHook|SetWebhook|webhookCallback|createWebhook)\s*\(/g,
    exclude: /^\s*(export\s+)?(public\s+|private\s+|static\s+|async\s+|def\s+|function\s+|func\s+)*(setWebhook|set_webhook|setWebHook|SetWebhook)\s*\([^)]*\)\s*(->\s*[\w\[\], ]+|:\s*[\w<>[\]., |]+)?\s*[{:]\s*$/,
    cwe: 'CWE-345',
    guide: 'BOT.md#webhook-secret',
    message: 'Without secret_token, anyone who learns the webhook URL can POST fake updates (fake users, fake payments, fake admin commands).',
    fix: 'Pass secret_token to setWebhook and reject requests whose X-Telegram-Bot-Api-Secret-Token header does not match.',
  },
  {
    id: 'TMA-BOT-001',
    title: 'Admin check by username',
    severity: 'medium',
    files: CODE,
    pattern: /\.username\s*(===|==)\s*['"]@?\w+['"]|\busername\s+in\s+\w*(ADMIN|admin|Admin)\w*|(ADMIN|admin|Admin)\w*\.(includes|contains|indexOf)\(\s*[\w.]*\.username\b/g,
    cwe: 'CWE-290',
    guide: 'BOT.md#admins-by-numeric-id',
    message: 'Usernames can be changed, released and claimed by someone else. A username-based admin list can be taken over.',
    fix: 'Compare from_user.id (numeric) against a server-side list of admin ids.',
  },
  {
    id: 'TMA-BOT-002',
    title: 'User-controlled text in an HTML-formatted message',
    severity: 'low',
    files: CODE,
    pattern: /(f["'][^"'\n]*\{[^}\n]*(first_name|last_name|full_name|username|\.text|caption)[^}\n]*\}[^"'\n]*["']|`[^`\n]*\$\{[^}\n]*(first_name|last_name|username|\.text|caption)[^}\n]*\}[^`\n]*`)[^\n]*parse_mode\s*[:=]\s*(['"]HTML['"]|ParseMode\.HTML)/g,
    exclude: /escape|html\.quote|quote_html|escapeHtml|html_decoration|hd\.quote/,
    cwe: 'CWE-116',
    guide: 'BOT.md#html-injection-in-messages',
    message: 'Names and message text can contain HTML. Unescaped, they break the message or inject links and formatting into what the bot sends.',
    fix: 'Escape user values (html.escape / aiogram html.quote / your library helper) or send them as entities instead of HTML.',
  },

  // ---------------------------------------------------------------- payments
  {
    id: 'TMA-PAY-001',
    title: 'Purchase granted from the client invoice callback',
    severity: 'high',
    files: isFrontend,
    pattern: /(status|invoiceStatus|result)\s*(===|==)\s*['"]paid['"]/g,
    cwe: 'CWE-602',
    guide: 'PAYMENTS.md#grant-on-successful_payment-only',
    message: 'The openInvoice callback runs in the user\'s browser. If it unlocks premium or credits, the user can fake it.',
    fix: 'Use the callback only to refresh the UI. Grant the purchase on the server when the bot receives the successful_payment update.',
  },
  {
    id: 'TMA-PAY-002',
    title: 'Pre-checkout query approved without checks',
    severity: 'low',
    files: SERVER_CODE,
    pattern: /answer_?[Pp]re_?[Cc]heckout_?[Qq]uery\(\s*[\w.]*\s*,\s*(true|ok\s*=\s*True)\s*\)|answerPreCheckoutQuery\(\s*true\s*\)|answer\(\s*ok\s*=\s*True\s*\)/g,
    nearbyExclude: { pattern: /invoice_payload|invoicePayload|total_amount|totalAmount/, before: 10 },
    cwe: 'CWE-20',
    guide: 'PAYMENTS.md#validate-the-pre-checkout-query',
    message: 'Approving every pre_checkout_query means stock, price and payload are never checked before money is taken.',
    fix: 'Look up invoice_payload on the server, check the item still exists, the amount and currency match, then answer ok=True; otherwise answer ok=False with an error message.',
  },

  // ---------------------------------------------------------------- frontend
  {
    id: 'TMA-WEB-001',
    title: 'HTML injection sink in the Mini App',
    severity: 'medium',
    files: isFrontend,
    pattern: /\.innerHTML\s*\+?=(?!=)|\.outerHTML\s*=(?!=)|insertAdjacentHTML\(|dangerouslySetInnerHTML|\bv-html\s*=|\{@html\s|document\.write\(/g,
    exclude: /\.(inner|outer)HTML\s*=\s*(['"])[^'"`$\n]*\2\s*;?\s*(\/\/.*)?$|\.innerHTML\s*=\s*``\s*;?$/,
    cwe: 'CWE-79',
    guide: 'FRONTEND.md#xss-in-a-mini-app',
    message: 'XSS inside a Mini App runs with the user\'s initData and can call your API as them.',
    fix: 'Render with textContent / framework bindings. If HTML is required, sanitize with DOMPurify.',
  },
  {
    id: 'TMA-WEB-002',
    title: 'start_param used as trusted input',
    severity: 'info',
    files: (p) => isFrontend(p) || isServer(p),
    pattern: /\bstart_param\b|\bstartParam\b|tgWebAppStartParam/g,
    cwe: 'CWE-20',
    guide: 'FRONTEND.md#start_param-is-attacker-controlled',
    message: 'start_param comes from the t.me link, which anyone can craft. Review where it flows (HTML, redirects, referral credit, SQL).',
    fix: 'Validate it against an allow-list format (e.g. /^[A-Za-z0-9_-]{1,64}$/) and never use it as a URL, HTML or an authorization decision.',
  },
  {
    id: 'TMA-WEB-003',
    title: 'Navigation to a variable URL',
    severity: 'low',
    files: isFrontend,
    pattern: /(window\.)?location(\.href)?\s*=\s*(?!['"`])[\w.[\]]+|\b(openLink|openTelegramLink)\(\s*(?!['"`])[\w.[\]]+|window\.open\(\s*(?!['"`])[\w.[\]]+/g,
    exclude: /location\.(origin|pathname|hostname)|=\s*(url_?for|route)\(/,
    cwe: 'CWE-601',
    guide: 'FRONTEND.md#open-redirects-and-openlink',
    message: 'If the URL comes from start_param, the query string or an API response, this is an open redirect or a javascript: URL sink.',
    fix: 'Allow-list hosts and require https: before navigating.',
  },
  {
    id: 'TMA-STO-001',
    title: 'Session or initData kept in localStorage',
    severity: 'medium',
    files: isFrontend,
    pattern: /localStorage\.setItem\(\s*['"`][^'"`]*(token|session|initData|init_data|jwt|auth)[^'"`]*['"`]/gi,
    cwe: 'CWE-922',
    guide: 'FRONTEND.md#storage',
    message: 'localStorage is readable by any script on the origin (one XSS is enough) and outlives the Telegram session.',
    fix: 'Keep the session in memory and re-authenticate with initData on launch, or use short-lived tokens. For secrets on device, Telegram\'s SecureStorage where available.',
  },
  {
    id: 'TMA-NET-002',
    title: 'CORS allows any origin',
    severity: 'low',
    files: isServer,
    pattern: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]|cors\(\s*\)|cors\(\s*\{\s*origin\s*:\s*(['"]\*['"]|true)|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\]|CORS\(\s*app\s*\)|AllowAllOrigins\s*[:=]\s*true/g,
    cwe: 'CWE-942',
    guide: 'BACKEND.md#cors',
    message: 'Any website can call this API from a victim\'s browser. Usually harmless if auth is an explicit initData header, risky with cookies.',
    fix: 'Allow only your Mini App origin(s). Never combine a wildcard with credentials.',
  },

  // ---------------------------------------------------------------- logging
  {
    id: 'TMA-LOG-001',
    title: 'initData or token written to logs',
    severity: 'low',
    files: CODE,
    pattern: /(console\.(log|info|debug|warn)|print|logger?\.(info|debug|warning|warn)|logging\.(info|debug|warning)|error_log|log\.Print\w*|fmt\.Print\w*)\(\s*[^)\n]*\b(initData|init_data|initDataRaw|BOT_TOKEN|bot_token|botToken|secret_token)\b/g,
    cwe: 'CWE-532',
    guide: 'BACKEND.md#logging',
    message: 'Logged initData can be replayed until auth_date expires; a logged bot token is a full compromise.',
    fix: 'Log the Telegram user id and a request id instead. Scrub initData and tokens in your logger.',
  },
];

module.exports.helpers = { isFrontend, isServer };
