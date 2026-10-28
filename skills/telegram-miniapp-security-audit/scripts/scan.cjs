#!/usr/bin/env node
'use strict';
/**
 * telegram-miniapp-security-audit triage scanner (zero dependencies).
 *
 *   node scan.cjs <project-dir> [--out leads.json] [--sarif leads.sarif]
 *                               [--min-severity low] [--fail-on high]
 *                               [--include-tests] [--quiet]
 *
 * Output is a list of LEADS for the audit workflow to validate.
 * A lead is never a confirmed vulnerability on its own.
 *
 * Suppress a reviewed line with a trailing comment:  // tma-ignore: TMA-XXX-000 reason
 */

const fs = require('fs');
const path = require('path');
const RULES = require('./rules.cjs');

const VERSION = '0.1.1';
const TOOL = 'telegram-miniapp-security-audit';
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', '.next', '.nuxt', '.svelte-kit', '.output',
  'coverage', '.venv', 'venv', 'env', '__pycache__', '.mypy_cache', '.pytest_cache',
  'vendor', '.dart_tool', '.idea', '.vscode', '.turbo', '.cache', '.vercel', '.netlify',
]);
const MAX_FILE_BYTES = 1024 * 1024;
const MINIFIED = /\.min\.(js|css)$|[-.]bundle\.js$|\.map$/;
// Vendored copies of Telegram's own client SDK are not the project's code.
const VENDORED = /(^|\/)telegram-web-apps?\.js$/;
const LOCKFILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|composer\.lock|pubspec\.lock)$/;
const TEST_PATH = /(^|\/)(test|tests|__tests__|spec|specs|testing|fixtures?|e2e)\/|[._-](test|spec)\.(m?[jt]sx?|py|go)$|_test\.(py|go|dart)$|(^|\/)test_[^/]+\.py$/;

function parseArgs(argv) {
  const args = { dir: null, out: null, sarif: null, minSeverity: 'info', failOn: null, quiet: false, includeTests: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') args.out = argv[++i];
    else if (a === '--sarif') args.sarif = argv[++i];
    else if (a === '--min-severity') args.minSeverity = argv[++i];
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--include-tests') args.includeTests = true;
    else if (a === '-h' || a === '--help') args.help = true;
    else if (a === '-v' || a === '--version') args.version = true;
    else if (!args.dir) args.dir = a;
    else throw new Error(`Unexpected argument: ${a}`);
  }
  for (const [key, flag] of [['minSeverity', '--min-severity'], ['failOn', '--fail-on']]) {
    if (args[key] && !SEVERITIES.includes(args[key])) {
      throw new Error(`${flag} must be one of ${SEVERITIES.join(', ')}`);
    }
  }
  return args;
}

function* walk(dir, root) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full, root);
    } else if (e.isFile()) {
      yield path.relative(root, full).split(path.sep).join('/');
    }
  }
}

function lineInfo(text, index) {
  let line = 1;
  let start = 0;
  for (let i = 0; i < index; i++) {
    if (text.charCodeAt(i) === 10) { line++; start = i + 1; }
  }
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  return { line, column: index - start + 1, text: text.slice(start, end) };
}

function redact(snippet) {
  // Never echo full secrets: long tokens mixing letters and digits keep only 6 chars,
  // and anything shaped like a bot token keeps only its numeric bot id.
  return snippet
    .replace(/\b(\d{8,10}):AA[0-9A-Za-z_-]{33}\b/g, '$1:AA…')
    .replace(/[A-Za-z0-9_\-+/=]{24,}/g, (tok) =>
      (/\d/.test(tok) && /[A-Za-z]/.test(tok) ? tok.slice(0, 6) + '…' : tok))
    .trim()
    .slice(0, 200);
}

function fileMatches(rule, rel) {
  return typeof rule.files === 'function' ? rule.files(rel) : rule.files.test(rel);
}

function scan(rootDir, opts = {}) {
  const minIdx = SEVERITIES.indexOf(opts.minSeverity || 'info');
  const root = path.resolve(rootDir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    throw new Error(`Not a directory: ${rootDir}`);
  }
  const leads = [];
  let filesScanned = 0;
  let testFilesSkipped = 0;

  for (const rel of walk(root, root)) {
    if (MINIFIED.test(rel) || LOCKFILE.test(rel) || VENDORED.test(rel)) continue;
    if (!opts.includeTests && TEST_PATH.test(rel)) { testFilesSkipped++; continue; }
    const rules = RULES.filter((r) => fileMatches(r, rel) && SEVERITIES.indexOf(r.severity) >= minIdx);
    if (!rules.length) continue;
    const full = path.join(root, rel);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.size > MAX_FILE_BYTES) continue;
    const text = fs.readFileSync(full, 'utf8');
    if (text.includes('\u0000')) continue; // binary
    filesScanned++;

    for (const rule of rules) {
      if (rule.exclude && rule.exclude.test(rel)) continue;
      if (rule.fileRequires && !rule.fileRequires.test(text)) continue;
      if (rule.fileAbsent && rule.fileAbsent.test(text)) continue;
      const fileLevel = Boolean(rule.fileRequires || rule.fileAbsent);
      const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
      const re = new RegExp(rule.pattern.source, flags);
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0].length === 0) { re.lastIndex++; continue; }
        const info = lineInfo(text, m.index);
        if (rule.exclude && rule.exclude.test(info.text)) continue;
        if (rule.nearbyExclude) {
          const lines = text.slice(0, m.index).split('\n');
          const window = lines.slice(Math.max(0, lines.length - 1 - rule.nearbyExclude.before)).join('\n');
          if (rule.nearbyExclude.pattern.test(window)) continue;
        }
        const ignore = info.text.match(/tma-ignore(?::\s*([A-Z0-9,\- ]+))?/);
        if (ignore && (!ignore[1] || ignore[1].includes(rule.id))) continue;
        leads.push({
          rule: rule.id,
          title: rule.title,
          severity_hint: rule.severity,
          file: rel,
          line: info.line,
          column: info.column,
          snippet: redact(info.text),
          cwe: rule.cwe,
          guide: rule.guide,
          message: rule.message,
          fix: rule.fix,
        });
        if (fileLevel) break;
      }
    }
  }

  leads.sort((a, b) =>
    SEVERITIES.indexOf(b.severity_hint) - SEVERITIES.indexOf(a.severity_hint) ||
    a.file.localeCompare(b.file) || a.line - b.line);

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const l of leads) counts[l.severity_hint]++;

  return {
    tool: `${TOOL}/scan`,
    version: VERSION,
    target: path.basename(root),
    generated_at: new Date().toISOString(),
    files_scanned: filesScanned,
    test_files_skipped: testFilesSkipped,
    rules_loaded: RULES.length,
    counts,
    note: 'Leads are triage hints. Each must be traced and validated before it is reported as a finding.',
    leads,
  };
}

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SARIF_SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '1.0' };

function toSarif(result) {
  const used = [...new Set(result.leads.map((l) => l.rule))];
  const rules = RULES.filter((r) => used.includes(r.id)).map((r) => ({
    id: r.id,
    name: r.title.replace(/[^A-Za-z0-9]+/g, ' ').trim().replace(/ (\w)/g, (_, c) => c.toUpperCase()).replace(/^\w/, (c) => c.toUpperCase()),
    shortDescription: { text: r.title },
    fullDescription: { text: r.message },
    help: { text: `${r.fix}\n\nGuide: skills/${TOOL}/checks/${r.guide}` },
    properties: { tags: ['security', 'telegram', r.cwe], 'security-severity': SARIF_SCORE[r.severity] },
  }));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: TOOL, version: VERSION, informationUri: 'https://github.com/MBotirjonDev/telegram-miniapp-audit', rules } },
      results: result.leads.map((l) => ({
        ruleId: l.rule,
        level: SARIF_LEVEL[l.severity_hint],
        message: { text: `${l.title}. ${l.message} (lead: validate before reporting)` },
        locations: [{ physicalLocation: { artifactLocation: { uri: l.file }, region: { startLine: l.line, startColumn: l.column } } }],
      })),
    }],
  };
}

function printHuman(result) {
  const colors = { critical: 35, high: 31, medium: 33, low: 36, info: 90 };
  const tty = process.stdout.isTTY;
  const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
  console.log(`\n${TOOL} · ${result.target} · ${result.files_scanned} files · ${result.rules_loaded} rules\n`);
  if (!result.leads.length) { console.log('No leads. Run the full skill workflow for logic, auth and payment issues.\n'); return; }
  for (const l of result.leads) {
    console.log(`${c(colors[l.severity_hint], l.severity_hint.toUpperCase().padEnd(8))} ${l.rule.padEnd(12)} ${l.title}`);
    console.log(`         ${l.file}:${l.line}`);
    console.log(`         ${c(90, l.snippet)}`);
  }
  const summary = SEVERITIES.slice().reverse().map((s) => `${s}: ${result.counts[s]}`).join('  ');
  console.log(`\n${result.leads.length} leads  (${summary})`);
  console.log('Leads are hints, not findings. Validate each one (see SKILL.md, phase 4).\n');
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n');
}

function main() {
  let args;
  try { args = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (args.version) { console.log(VERSION); return; }
  if (args.help || !args.dir) {
    console.log('Usage: node scan.cjs <project-dir> [--out leads.json] [--sarif leads.sarif] [--min-severity info|low|medium|high|critical] [--fail-on <severity>] [--include-tests] [--quiet]');
    process.exit(args.help ? 0 : 2);
  }
  let result;
  try { result = scan(args.dir, { minSeverity: args.minSeverity, includeTests: args.includeTests }); } catch (e) { console.error(e.message); process.exit(2); }
  if (args.out) writeJson(args.out, result);
  if (args.sarif) writeJson(args.sarif, toSarif(result));
  if (!args.quiet) printHuman(result);
  if (args.failOn) {
    const threshold = SEVERITIES.indexOf(args.failOn);
    if (result.leads.some((l) => SEVERITIES.indexOf(l.severity_hint) >= threshold)) process.exit(1);
  }
}

if (require.main === module) main();
module.exports = { scan, toSarif, redact, SEVERITIES, VERSION };
