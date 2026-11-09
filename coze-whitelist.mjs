#!/usr/bin/env node
/**
 * coze-whitelist — manage the shell-command whitelist of Coze Desktop (扣子桌面版).
 *
 * Coze Desktop asks for manual approval every time an agent runs a shell command
 * that is not on the per-device "always allow" whitelist stored on the Coze
 * server. Clicking "Always allow" (始终允许) in the popup inserts one rule per
 * command prefix. This tool does the same thing in bulk, so you stop seeing
 * hundreds of approval popups.
 *
 * How it works (fully local, your own account):
 *   1. Optionally restarts your local Coze Desktop with --remote-debugging-port
 *      (the app is restored to normal mode afterwards).
 *   2. Reads the coze.cn session cookies of YOUR logged-in session via the
 *      Chrome DevTools Protocol. Cookies are kept in memory only — never
 *      printed, never written to disk.
 *   3. Calls the same endpoints the app itself calls:
 *        GET  /api/coze_claw/shell_permission          (list rules)
 *        POST /api/coze_claw/shell_permission/insert   (add rules)
 *        POST /api/coze_claw/shell_permission/delete   (remove rules by id)
 *
 * Requirements: macOS, Node.js >= 22, Coze Desktop installed and logged in.
 * This is an unofficial tool and is not affiliated with ByteDance/Coze.
 *
 * Usage:
 *   node coze-whitelist.mjs list [--json]
 *   node coze-whitelist.mjs add <command> [command...]
 *   node coze-whitelist.mjs add --preset js|python|infra|recommended
 *   node coze-whitelist.mjs remove <command> [command...]
 *
 * Options:
 *   --port <n>          CDP debug port (default 9222)
 *   --api-base <url>    API base (default https://www.coze.cn)
 *   --device-id <id>    Device id (default: auto from ~/.coze/desktop/device.json)
 *   --app-name <name>   macOS app name (default: 扣子; international build: Coze)
 *   --no-manage         Do not quit/relaunch the app; assume the debug port is
 *                       already open (e.g. you started the app with the flag)
 *   --yes               Non-interactive; also required to whitelist high-risk
 *                       commands (rm, sudo, osascript, bash, ...)
 *   --json              Machine-readable output for `list`
 */

import { readFileSync, existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

// ---------------------------------------------------------------------------
// Curated presets (deliberately exclude high-risk commands; see HIGH_RISK)
// ---------------------------------------------------------------------------
const PRESETS = {
  js: ['node', 'npm', 'npx', 'pnpm', 'yarn', 'bun', 'deno', 'tsx', 'ts-node', 'gh'],
  python: ['python', 'python3', 'pip', 'pip3', 'uv', 'uvx', 'poetry', 'conda', 'pipx'],
  infra: ['docker', 'docker-compose', 'kubectl', 'helm', 'terraform', 'ssh', 'scp', 'rsync'],
  recommended: [
    // file / text basics beyond the app's built-in read-only defaults
    'cp', 'mv', 'ln', 'tar', 'unzip', 'zip', 'gzip', 'gunzip', 'sed', 'awk',
    'xargs', 'sort', 'date', 'env', 'printenv', 'man', 'open', 'pbcopy', 'pbpaste',
    'tree', 'ps', 'top', 'lsof', 'sw_vers',
    // language toolchains
    'node', 'npm', 'npx', 'pnpm', 'yarn', 'bun', 'deno', 'tsx', 'ts-node',
    'git', 'python', 'python3', 'pip', 'pip3', 'uv', 'uvx', 'poetry', 'conda',
    'pipx', 'pyenv', 'rbenv', 'php', 'composer', 'ruby', 'gem', 'bundle', 'perl',
    'swift', 'swiftc', 'dotnet', 'brew', 'cargo', 'rustc', 'go', 'java', 'javac',
    'mvn', 'gradle', 'make', 'cmake',
    // containers / infra / remote
    'docker', 'docker-compose', 'kubectl', 'helm', 'terraform', 'ssh', 'scp',
    'sftp', 'rsync', 'mosh',
    // databases / network / misc
    'sqlite3', 'psql', 'mysql', 'redis-cli', 'mongosh', 'ffmpeg', 'ffprobe',
    'convert', 'magick', 'curl', 'wget', 'ping', 'dig', 'nslookup', 'host', 'nc',
    'netstat', 'ifconfig', 'caffeinate', 'tmux', 'screen', 'watch', 'time',
    'timeout', 'nohup', 'yq', 'gh', 'xcodebuild', 'xcrun', 'pod'
  ]
};

// Commands that can destroy data, escalate privileges, or control the system.
// The tool refuses to whitelist these without --yes.
const HIGH_RISK = new Set([
  'rm', 'sudo', 'su', 'osascript', 'kill', 'killall', 'pkill', 'launchctl',
  'dd', 'mkfs', 'diskutil', 'shutdown', 'reboot', 'nvram', 'pmset', 'security',
  'spctl', 'csrutil', 'bash', 'sh', 'zsh', 'fish'
]);

// ---------------------------------------------------------------------------
// Tiny argv parser: --flag value | --flag=value | --bool
// ---------------------------------------------------------------------------
function parseArgv(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > -1) {
        opts[a.slice(2, eq)] = a.slice(eq + 1);
      } else if (argv[i + 1] && !argv[i + 1].startsWith('--')) {
        opts[a.slice(2)] = argv[++i];
      } else {
        opts[a.slice(2)] = true;
      }
    } else {
      opts._.push(a);
    }
  }
  return opts;
}

const opts = parseArgv(process.argv.slice(2));
const PORT = Number(opts.port || 9222);
const API_BASE = (opts['api-base'] || 'https://www.coze.cn').replace(/\/$/, '');
const APP_NAME = opts['app-name'] || '扣子';
const MANAGE = !opts['no-manage'];
const YES = !!opts.yes;
const cmd = opts._[0] || 'list';

// Progress/info messages go to stderr so that stdout stays clean data output
// (important for `list --json` consumers piping stdout).
const log = (...args) => console.error(...args);

function die(msg) {
  console.error(`error: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Device id: auto-detect from the desktop app's local config
// ---------------------------------------------------------------------------
function resolveDeviceId() {
  if (opts['device-id']) return String(opts['device-id']);
  const candidates = [
    join(homedir(), '.coze', 'desktop', 'device.json'),
    join(homedir(), '.coze', 'desktop', 'device.json'.toUpperCase())
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        const j = JSON.parse(readFileSync(p, 'utf-8'));
        if (j.deviceId) return String(j.deviceId);
      } catch { /* fall through */ }
    }
  }
  return die(`cannot auto-detect device id; pass --device-id (found in ~/.coze/desktop/device.json)`);
}

// ---------------------------------------------------------------------------
// App orchestration (macOS): normal mode <-> debug port mode
// ---------------------------------------------------------------------------
const IS_MAC = platform() === 'darwin';

function appRunning() {
  try {
    execFileSync('pgrep', ['-f', `${APP_NAME}.app/Contents/MacOS/`], { stdio: 'pipe' });
    return true;
  } catch { return false; }
}

function debugPortOpen() {
  try {
    const res = execFileSync('curl', ['-s', '--max-time', '2', `http://127.0.0.1:${PORT}/json/version`], { stdio: 'pipe' });
    return res.length > 0;
  } catch { return false; }
}

function quitApp() {
  try {
    execFileSync('osascript', ['-e', `tell application "${APP_NAME}" to quit`], { stdio: 'pipe' });
  } catch { /* may already be closed */ }
  for (let i = 0; i < 15; i++) {
    if (!appRunning()) return;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
}

function launchWithPort() {
  execFileSync('open', ['-a', APP_NAME, '--args', `--remote-debugging-port=${PORT}`], { stdio: 'pipe' });
}

function launchNormal() {
  execFileSync('open', ['-a', APP_NAME], { stdio: 'pipe' });
}

function waitForPort(seconds = 25) {
  for (let i = 0; i < seconds; i++) {
    if (debugPortOpen()) return true;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  return false;
}

async function ensureDebugApp() {
  if (debugPortOpen()) return { managed: false };
  if (!MANAGE) die(`nothing listening on 127.0.0.1:${PORT}. Start the app with --remote-debugging-port=${PORT} first, or drop --no-manage.`);
  if (!IS_MAC) die('automatic app management is macOS-only; start the app with the debug flag manually and pass --no-manage.');
  if (!appRunning() && !YES && process.stdin.isTTY) {
    process.stdout.write(`Will briefly restart "${APP_NAME}" with a local debug port to read your session. Continue? [y/N] `);
    const answer = await new Promise(r => {
      let buf = '';
      process.stdin.once('data', d => { buf += d; r(buf.trim().toLowerCase()); });
    });
    if (answer !== 'y' && answer !== 'yes') die('aborted by user');
  }
  log(`restarting "${APP_NAME}" with debug port ${PORT} (will restore normal mode afterwards)...`);
  quitApp();
  launchWithPort();
  if (!waitForPort()) die(`debug port ${PORT} did not open; is "${APP_NAME}" installed?`);
  return { managed: true };
}

async function restoreApp(managed) {
  if (!managed) return;
  quitApp();
  launchNormal();
  for (let i = 0; i < 10; i++) {
    if (appRunning()) break;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  log(`"${APP_NAME}" restored to normal mode (debug port closed).`);
}

// ---------------------------------------------------------------------------
// Minimal CDP client (Node >= 22 has global WebSocket and fetch)
// ---------------------------------------------------------------------------
function connectCdp(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let id = 0;
    const pending = new Map();
    ws.onopen = () => resolve({
      send(method, params = {}) {
        return new Promise((res, rej) => {
          const mid = ++id;
          pending.set(mid, { res, rej });
          ws.send(JSON.stringify({ id: mid, method, params }));
        });
      },
      close: () => ws.close()
    });
    ws.onerror = () => reject(new Error('websocket error'));
    ws.onmessage = ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { res, rej } = pending.get(msg.id);
        pending.delete(msg.id);
        msg.error ? rej(new Error(JSON.stringify(msg.error))) : res(msg.result);
      }
    };
  });
}

/** Read coze.cn session cookies via CDP. Memory only — never logged or saved. */
async function getSession() {
  let version;
  try {
    version = await (await fetch(`http://127.0.0.1:${PORT}/json/version`)).json();
  } catch { die(`debug port on 127.0.0.1:${PORT} is not reachable`); }
  const targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json();
  const page = targets.find(t => t.type === 'page' && (t.url || '').startsWith('coze-desktop://'));
  if (!page) die('main window target not found; is this the Coze desktop app?');
  const cdp = await connectCdp(page.webSocketDebuggerUrl);
  await cdp.send('Network.enable');
  let res = await cdp.send('Network.getCookies', { urls: [API_BASE, 'https://coze.cn'] });
  let cookies = res.cookies || [];
  if (!cookies.length) {
    res = await cdp.send('Storage.getCookies');
    cookies = (res.cookies || []).filter(c => (c.domain || '').includes('coze.cn'));
  }
  cdp.close();
  if (!cookies.length) die('no coze.cn session cookies found; log in to the desktop app first.');
  const host = new URL(API_BASE).host;
  return {
    cookieHeader: cookies.map(c => `${c.name}=${c.value}`).join('; '),
    cookieCount: cookies.length,
    cookieNames: cookies.map(c => c.name).sort(),
    userAgent: version['User-Agent'] || 'Mozilla/5.0'
  };
}

function apiHeaders(session) {
  return {
    Cookie: session.cookieHeader,
    'x-coze-desktop': DEVICE_ID,
    'x-coze-version': '3.5',
    'User-Agent': session.userAgent,
    Referer: `${API_BASE}/`,
    Origin: API_BASE
  };
}

// ---------------------------------------------------------------------------
// Whitelist API
// ---------------------------------------------------------------------------
let DEVICE_ID; // resolved once in main()

async function apiGet(path) {
  const r = await fetch(`${API_BASE}${path}`, { headers: apiHeaders(SESSION) });
  if (!r.ok) die(`GET ${path}: HTTP ${r.status}`);
  return r.json();
}

async function apiPost(path, body) {
  const r = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { ...apiHeaders(SESSION), 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!r.ok) die(`POST ${path}: HTTP ${r.status}`);
  return r.json();
}

async function listRules() {
  const j = await apiGet(`/api/coze_claw/shell_permission?device_id=${encodeURIComponent(DEVICE_ID)}`);
  if (j.code !== 0) die(`list failed: code=${j.code} msg=${j.msg || 'unknown'}`);
  return j.data?.rules || [];
}

const ruleId = r => r.id ?? r.rule_id ?? r.ID;
const rulePrefix = r => (Array.isArray(r.prefix) ? r.prefix[0] : r.prefix) ?? '';

async function addCommands(commands) {
  const rules = await listRules();
  const existing = new Set(rules.map(rulePrefix).map(s => s.trim()));
  const targets = [...new Set(commands.map(c => c.trim()).filter(Boolean))];
  if (!targets.length) die('no commands given');

  const risky = targets.filter(c => HIGH_RISK.has(c));
  if (risky.length && !YES) {
    die(`refusing to whitelist high-risk commands without --yes: ${risky.join(', ')}\n` +
        `these can delete data or escalate privileges; the popup is the last guardrail.`);
  }

  const missing = targets.filter(c => !existing.has(c));
  if (!missing.length) {
    log('all given commands are already whitelisted; nothing to do.');
    return;
  }
  const j = await apiPost('/api/coze_claw/shell_permission/insert', {
    device_id: DEVICE_ID,
    rules: missing.map(c => ({ prefix: [c], action: 'allow' }))
  });
  if (j.code !== 0) die(`insert failed: code=${j.code} msg=${j.msg || 'unknown'}`);
  log(`added ${missing.length} rule(s): ${missing.join(', ')}`);
  log(`whitelist now has ${(await listRules()).length} rule(s).`);
  log('note: the running app caches the list; restart the app (or wait for its cache to expire) to take effect.');
}

async function removeCommands(commands) {
  const rules = await listRules();
  const targets = new Set(commands.map(c => c.trim()).filter(Boolean));
  const matched = rules.filter(r => targets.has(rulePrefix(r).trim()));
  if (!matched.length) {
    log('no matching rules found for: ' + [...targets].join(', '));
    return;
  }
  const ids = matched.map(ruleId).filter(v => v !== undefined);
  if (ids.length !== matched.length) {
    die('server rules do not expose ids; cannot delete. Please report this at the project issue page.');
  }
  const j = await apiPost('/api/coze_claw/shell_permission/delete', { device_id: DEVICE_ID, rule_ids: ids });
  if (j.code !== 0) die(`delete failed: code=${j.code} msg=${j.msg || 'unknown'}`);
  log(`removed ${ids.length} rule(s): ${matched.map(rulePrefix).join(', ')}`);
  log(`whitelist now has ${(await listRules()).length} rule(s).`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
let SESSION;

async function main() {
  DEVICE_ID = resolveDeviceId();

  switch (cmd) {
    case 'list': {
      const { managed } = await ensureDebugApp();
      try {
        SESSION = await getSession();
        const rules = await listRules();
        if (opts.json) {
          console.log(JSON.stringify({ device_id: DEVICE_ID, count: rules.length, rules }, null, 2));
        } else {
          console.log(`device ${DEVICE_ID}: ${rules.length} rule(s)`);
          for (const r of rules) console.log(`  ${rulePrefix(r)}\t${r.action || 'allow'}\t${ruleId(r) ?? ''}`);
        }
      } finally {
        await restoreApp(managed);
      }
      break;
    }
    case 'add': {
      let commands = [];
      if (opts.preset) {
        const preset = PRESETS[String(opts.preset)];
        if (!preset) die(`unknown preset "${opts.preset}"; available: ${Object.keys(PRESETS).join(', ')}`);
        commands = preset;
      } else {
        commands = opts._.slice(1);
      }
      if (!commands.length) die('nothing to add; pass command names or --preset <name>');
      const { managed } = await ensureDebugApp();
      try {
        SESSION = await getSession();
        await addCommands(commands);
      } finally {
        await restoreApp(managed);
      }
      break;
    }
    case 'remove': {
      const commands = opts._.slice(1);
      if (!commands.length) die('nothing to remove; pass command names');
      const { managed } = await ensureDebugApp();
      try {
        SESSION = await getSession();
        await removeCommands(commands);
      } finally {
        await restoreApp(managed);
      }
      break;
    }
    case 'help':
    case '--help':
    case '-h':
      console.log(`coze-whitelist — manage Coze Desktop shell whitelist

  node coze-whitelist.mjs list [--json]
  node coze-whitelist.mjs add <command...> | --preset js|python|infra|recommended
  node coze-whitelist.mjs remove <command...>

Options: --port --api-base --device-id --app-name --no-manage --yes --json`);
      break;
    default:
      die(`unknown command "${cmd}"; try: list | add | remove | help`);
  }
}

main().catch(e => die(e.message));
