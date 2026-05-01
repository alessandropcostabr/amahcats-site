const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

// ---------- Carregar .env (sem dependencia externa) ----------
try {
  const envContent = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');
    if (!process.env[key]) process.env[key] = val;
  }
} catch { /* .env ausente */ }

const PORT = process.env.PORT || 8083;
const PUBLIC_DIR = __dirname;

// ---------- Integracao CRM (intake via LAN - mesmo LATE do IACD) ----------
const CRM_INTAKE_URL = process.env.CRM_INTAKE_URL || 'http://192.168.0.253:3100/api/crm/intake/iacd';
const CRM_INTAKE_TOKEN = process.env.CRM_INTAKE_TOKEN || '';

// ---------- HMAC Secrets (seguranca de formularios) ----------
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || '';

const OPPORTUNITY_HMAC_SECRET = process.env.OPPORTUNITY_HMAC_SECRET || '';
const PREFILL_TOKEN_SECRET = process.env.PREFILL_TOKEN_SECRET || '';

// ---------- SMTP + Alertas ----------
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = process.env.SMTP_SECURE === '1';
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || '';
const ALERT_EMAIL_TO = process.env.ALERT_EMAIL_TO || '';

// ---------- Abrigo API (late-abrigo, rede local) ----------
const ABRIGO_API        = process.env.ABRIGO_API_URL        || 'http://192.168.0.125:3200';
const ABRIGO_PUBLIC_URL = process.env.ABRIGO_PUBLIC_URL     || 'https://abrigo.late.app.br';

// Dominio canonico e secundarios (redirect 301)
const CANONICAL_DOMAIN = 'amahcats.com.br';
const SECONDARY_DOMAINS = [
  'www.amahcats.com.br',
  'amahcats.com',
  'www.amahcats.com',
];

// Mapeamento de rotas para arquivos
const routes = {
  '/': 'index.html',
  '/privacidade': 'privacidade.html',
  '/privacidade.html': 'privacidade.html',
  '/adocao-form': 'adocao-form.html',
  '/adocao-form.html': 'adocao-form.html',
  '/favicon.ico': 'assets/amahcats_logo.png',
  '/robots.txt': 'robots.txt',
};

const publicPathResolvers = [
  {
    match: function(pathname) { return Object.prototype.hasOwnProperty.call(routes, pathname); },
    resolve: function(pathname) { return routes[pathname]; },
  },
  {
    match: function(pathname) { return pathname.startsWith('/assets/'); },
    resolve: function(pathname) { return pathname.slice(1); },
  },
  {
    match: function(pathname) { return pathname.startsWith('/css/'); },
    resolve: function(pathname) { return pathname.slice(1); },
  },
];

const blockedInternalPathPatterns = [
  /^\/server\.js$/i,
  /^\/package(?:-lock)?\.json$/i,
  /^\/README(?:\.[^/]+)?$/i,
  /^\/CLAUDE\.md$/i,
  /^\/TO_DO\.md$/i,
  /^\/ecosystem\.config\.js$/i,
  /^\/\.env$/i,
  /^\/\.env\./i,
];

// Tipos MIME
const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain',
  '.xml': 'application/xml',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.webp': 'image/webp',
};

// ---------- Padroes de scanners/bots ----------
const SCANNER_PATTERNS = [
  /^\/\.env$/, /^\/\.env\./, /^\/\.git/, /^\/\.vscode/,
  /^\/\.DS_Store$/, /^\/\.htaccess$/,
  /^\/admin/, /^\/wp-admin/, /^\/wp-login/, /^\/wp-json/,
  /^\/xmlrpc\.php$/, /^\/@vite/, /^\/node_modules/,
  /^\/vendor\//, /^\/src\//, /^\/test/,
  /^\/cgi-bin/, /^\/boaform/, /^\/phpinfo/, /^\/phpmyadmin/i,
  /^\/actuator/, /^\/debug\//, /^\/console/,
  /^\/backup/, /^\/dump/,
  /~$/, /\.bak$/, /\.swp$/, /\.php$/, /\.sql$/, /\.tar\.gz$/, /\.zip$/,
  /\.asp$/i, /\.aspx$/i, /\.jsp$/i,
  /^\/shell/i, /^\/cmd/i, /^\/eval/i,
  /^\/database/i, /^\/mysql/i, /^\/pma/i,
  /^\/jenkins/i, /^\/solr/i, /^\/telescope/i,
  /^\/elfinder/i, /^\/filemanager/i,
  /^\/graphql/i, /^\/api\/graphql/i,
  /^\/\.svn/i, /^\/\.hg/i,
  /^\/wp-content\//i, /^\/wp-includes\//i,
];

const NOISY_404_PATTERNS = [
  /^\/favicon(\.|-)/,
  /^\/apple-touch-icon/,
  /^\/browserconfig\.xml$/,
  /^\/wp-content\//, /^\/wp-includes\//,
  /^\/icons\//, /^\/images\//, /^\/res\//,
];

const ENCODED_PATTERNS = [
  /%3A(?:\/\/)/, /^\/https%3A/, /^\/tel%3A/, /^\/mailto%3A/,
];

// ---------- Headers de seguranca ----------
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '0',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://static.cloudflareinsights.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "frame-src https://challenges.cloudflare.com",
    "connect-src 'self' https://viacep.com.br https://challenges.cloudflare.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
};

// ---------- Rate limiting ----------
const rateLimitBuckets = new Map([
  ['html', { windowMs: 60_000, max: 90 }],
  ['asset', { windowMs: 60_000, max: 300 }],
  ['noisy-404', { windowMs: 60_000, max: 20 }],
  ['scanner', { windowMs: 60_000, max: 8 }],
]);
const rateLimitMap = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.start > entry.windowMs) rateLimitMap.delete(key);
  }
  if (rateLimitMap.size > 10000) rateLimitMap.clear();
}, 5 * 60 * 1000);

function isScannerPath(pathname) {
  return SCANNER_PATTERNS.some(p => p.test(pathname)) ||
         ENCODED_PATTERNS.some(p => p.test(pathname));
}

function isNoisy404Path(pathname) {
  return NOISY_404_PATTERNS.some(p => p.test(pathname));
}

function isAssetPath(pathname) {
  if (pathname.startsWith('/assets/') || pathname.startsWith('/css/')) return true;
  var ext = path.extname(pathname).toLowerCase();
  return Boolean(ext && mimeTypes[ext] && ext !== '.html');
}

function resolvePublicFilePath(pathname) {
  for (var i = 0; i < publicPathResolvers.length; i += 1) {
    if (publicPathResolvers[i].match(pathname)) {
      return publicPathResolvers[i].resolve(pathname);
    }
  }
  return null;
}

function isBlockedInternalPath(pathname) {
  return blockedInternalPathPatterns.some(pattern => pattern.test(pathname));
}

function getRateLimitBucket(pathname, flags) {
  if (flags.isScanner) return 'scanner';
  if (flags.isNoisy404) return 'noisy-404';
  if (isAssetPath(pathname)) return 'asset';
  return 'html';
}

function isRateLimited(bucket, ip) {
  if (!bucket) return false;
  var config = rateLimitBuckets.get(bucket);
  if (!config) return false;
  var now = Date.now();
  var key = bucket + ':' + ip;
  var entry = rateLimitMap.get(key);
  if (!entry || now - entry.start > entry.windowMs) {
    rateLimitMap.set(key, { count: 1, start: now, windowMs: config.windowMs });
    return false;
  }
  entry.count++;
  return entry.count > config.max;
}

// ---------- IP helpers ----------
const TRUSTED_PROXY_PREFIXES = [
  '127.', '::1', '::ffff:127.', '192.168.', '10.',
  '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
  '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
  '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
];

function getClientIp(req) {
  var remote = req.socket.remoteAddress || '';
  var isTrusted = TRUSTED_PROXY_PREFIXES.some(p => remote.startsWith(p));
  if (!isTrusted) return remote || 'unknown';
  var cfIp = (req.headers['cf-connecting-ip'] || '').trim();
  if (cfIp && /^[\d.:a-fA-F]+$/.test(cfIp)) return cfIp;
  var forwarded = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (forwarded && /^[\d.:a-fA-F]+$/.test(forwarded)) return forwarded;
  return remote || 'unknown';
}

function localTimestamp() {
  return new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
}

// ---------- Turnstile verification ----------
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    var body = JSON.stringify({
      secret: TURNSTILE_SECRET,
      response: token,
      remoteip: ip,
    });
    var resp = await new Promise(function(resolve, reject) {
      var req = require('https').request({
        hostname: 'challenges.cloudflare.com',
        path: '/turnstile/v0/siteverify',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      }, function(res) {
        var data = '';
        res.on('data', function(chunk) { data += chunk; });
        res.on('end', function() { resolve(JSON.parse(data)); });
      });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
    return resp.success === true;
  } catch (err) {
    console.error('[' + localTimestamp() + '] Turnstile verification error:', err.message);
    return false;
  }
}

// ---------- Rate limiting para /api/adocao e /api/entrevista ----------
const ADOPT_RATE_LIMIT_WINDOW = 60 * 1000;
const ADOPT_RATE_LIMIT_MAX = 10;
const adoptRateLimitMap = new Map();

setInterval(() => {
  var now = Date.now();
  for (var [ip, entry] of adoptRateLimitMap) {
    if (now - entry.start > ADOPT_RATE_LIMIT_WINDOW) adoptRateLimitMap.delete(ip);
  }
  if (adoptRateLimitMap.size > 10000) adoptRateLimitMap.clear();
}, 5 * 60 * 1000);

function isAdoptRateLimited(ip) {
  var now = Date.now();
  var entry = adoptRateLimitMap.get(ip);
  if (!entry || now - entry.start > ADOPT_RATE_LIMIT_WINDOW) {
    adoptRateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }
  entry.count++;
  return entry.count > ADOPT_RATE_LIMIT_MAX;
}

const BODY_LIMIT = 8192;
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

function isValidBRPhone(digits) {
  if (digits.length !== 10 && digits.length !== 11) return false;
  var ddd = parseInt(digits.slice(0, 2), 10);
  if (ddd < 11) return false;
  if (digits.length === 11 && digits[2] !== '9') return false;
  if (digits.length === 10 && (digits[2] === '0' || digits[2] === '1')) return false;
  return true;
}

function sendJson(res, status, data) {
  var body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function normalizePhoneBR(raw) {
  var digits = String(raw || '').replace(/\D/g, '');
  if (digits.length === 13 && digits.startsWith('55')) return digits;
  if (digits.length === 11) return '55' + digits;
  if (digits.length === 10) return '55' + digits;
  return digits;
}

function maskEmail(email) {
  if (!email) return '';
  var atIdx = email.indexOf('@');
  if (atIdx <= 1) return '***@' + email.slice(atIdx + 1);
  return email[0] + '***@' + email.slice(atIdx + 1);
}

function maskPhone(phone) {
  if (!phone) return '';
  return phone.slice(0, 4) + '****' + phone.slice(-2);
}

// ---------- SMTP via Python ----------

function sanitizeMailHeader(value) {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim();
}

async function sendMailViaSmtp({ to, from, subject, text }) {
  if (!SMTP_HOST) return false;

  var pythonCode = [
    'import os, ssl, smtplib',
    'from email.message import EmailMessage',
    'msg = EmailMessage()',
    'msg["From"] = os.environ["MAIL_FROM"]',
    'msg["To"] = os.environ["MAIL_TO"]',
    'msg["Subject"] = os.environ["MAIL_SUBJECT"]',
    'msg.set_content(os.environ["MAIL_TEXT"])',
    'host = os.environ["SMTP_HOST"]',
    'port = int(os.environ["SMTP_PORT"])',
    'secure = os.environ.get("SMTP_SECURE") == "1"',
    'user = os.environ.get("SMTP_USER") or None',
    'password = os.environ.get("SMTP_PASS") or None',
    'timeout = 20',
    'if secure:',
    '    server = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=timeout)',
    'else:',
    '    server = smtplib.SMTP(host, port, timeout=timeout)',
    '    server.starttls(context=ssl.create_default_context())',
    'if user and password:',
    '    server.login(user, password)',
    'server.send_message(msg)',
    'server.quit()',
  ].join('\n');

  await new Promise((resolve, reject) => {
    var child = spawn('/usr/bin/python3', ['-c', pythonCode], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: {
        PATH: process.env.PATH || '/usr/bin:/bin',
        HOME: process.env.HOME || '/tmp',
        SMTP_HOST,
        SMTP_PORT: String(SMTP_PORT),
        SMTP_SECURE: SMTP_SECURE ? '1' : '0',
        SMTP_USER,
        SMTP_PASS,
        MAIL_TO: sanitizeMailHeader(to),
        MAIL_FROM: sanitizeMailHeader(from),
        MAIL_SUBJECT: sanitizeMailHeader(subject),
        MAIL_TEXT: text,
      },
    });
    var stderr = '';
    child.stderr.on('data', chunk => { stderr += chunk.toString(); });
    child.on('close', code => {
      if (code === 0) resolve();
      else reject(new Error('SMTP python exit=' + code + ': ' + stderr.trim().slice(0, 200)));
    });
    child.on('error', reject);
  });

  return true;
}

// ---------- Alertas por email ----------

async function sendContingencyAlert(data) {
  if (!SMTP_HOST || !ALERT_EMAIL_TO) return;
  try {
    await sendMailViaSmtp({
      to: ALERT_EMAIL_TO,
      from: SMTP_FROM || ALERT_EMAIL_TO,
      subject: '[AmahCats] Contingencia - formulario adocao (LATE indisponivel)',
      text: [
        'O formulario de adocao do site AmahCats nao conseguiu enviar ao CRM.',
        '',
        'Data/Hora: ' + new Date().toISOString(),
        'Nome: ' + (data.nome || 'nao informado'),
        'E-mail: ' + (data.email || 'nao informado'),
        'Telefone: ' + (data.telefone || 'nao informado'),
        'Especie: ' + (data.especie || 'nao informado'),
        'Erro: ' + (data.error || 'desconhecido'),
        '',
        'JSON salvo em /tmp/amahcats-contingencia/ no DarkStarII (.254).',
        'Reprocessar manualmente quando LATE voltar.',
      ].join('\n'),
    });
    console.info('[' + localTimestamp() + '] EMAIL ALERTA contingencia enviado para ' + ALERT_EMAIL_TO);
  } catch (mailErr) {
    console.error('[' + localTimestamp() + '] EMAIL ALERTA contingencia FALHOU: ' + mailErr.message);
  }
}

async function sendIdentityConflictAlert(data) {
  if (!SMTP_HOST || !ALERT_EMAIL_TO) return;
  try {
    await sendMailViaSmtp({
      to: ALERT_EMAIL_TO,
      from: SMTP_FROM || ALERT_EMAIL_TO,
      subject: '[AmahCats] IDENTITY_CONFLICT - formulario adocao',
      text: [
        'O formulario de adocao do site AmahCats recebeu um IDENTITY_CONFLICT no CRM.',
        '',
        'Data/Hora: ' + new Date().toISOString(),
        'Nome: ' + (data.nome || 'nao informado'),
        'E-mail: ' + (data.email || 'nao informado'),
        'Telefone: ' + (data.telefone || 'nao informado'),
        'Especie: ' + (data.especie || 'nao informado'),
        'HTTP status: ' + (data.statusCode || 'nao informado'),
        'Mensagem CRM: ' + (data.message || 'nao informado'),
      ].join('\n'),
    });
    console.info('[' + localTimestamp() + '] EMAIL ALERTA enviado: tipo=IDENTITY_CONFLICT to=' + ALERT_EMAIL_TO);
  } catch (mailErr) {
    console.error('[' + localTimestamp() + '] EMAIL ALERTA falhou: tipo=IDENTITY_CONFLICT msg=' + mailErr.message);
  }
}

function saveContingencyJson(data) {
  try {
    var dir = '/tmp/amahcats-contingencia';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    var existing = fs.readdirSync(dir);
    if (existing.length >= 500) {
      console.error('[' + localTimestamp() + '] Contingencia CHEIA (500 arquivos) - dado PERDIDO');
      return null;
    }
    var filename = Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '.json';
    fs.writeFileSync(path.join(dir, filename), JSON.stringify(data, null, 2));
    console.warn('[' + localTimestamp() + '] Contingencia salva: ' + filename);
    return filename;
  } catch (fsErr) {
    console.error('[' + localTimestamp() + '] Contingencia disco FALHOU: ' + fsErr.message);
    return null;
  }
}

async function forwardToIntake({ nome, email, telefone, especie, mensagem, clientIp, clientUa, howFound }) {
  var payload = {
    name: nome,
    phone: normalizePhoneBR(telefone) || undefined,
    email: email || undefined,
    species_preference: especie || undefined,
    message: mensagem || undefined,
    client_ip: clientIp || undefined,
    client_ua: clientUa || undefined,
    how_found: howFound || undefined,
    intake_source: 'amahcats',
  };

  var response = await fetch(CRM_INTAKE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-intake-token': CRM_INTAKE_TOKEN,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(5000),
  });

  var result = await response.json();
  if (!response.ok) {
    var err = new Error(result.error || 'CRM intake HTTP ' + response.status);
    err.statusCode = response.status;
    err.errorCode = result.error_code || null;
    err.userMessage = result.error || null;
    err.field = result.field || null;
    throw err;
  }
  return result;
}

// ---------- Abrigo: catalogo publico ----------

var PAGE_SHELL_HEAD = '<!DOCTYPE html><html lang="pt-BR"><head>'
  + '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
  + '<link rel="icon" type="image/png" href="/assets/amahcats_logo.png">'
  + '<link rel="stylesheet" href="/css/style.css?v=4">'
  + '<link rel="preconnect" href="https://fonts.googleapis.com">'
  + '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
  + '<link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700&family=Poppins:wght@600;700;800;900&display=swap" rel="stylesheet">'
  + '<style>'
  + '.abrigo-hero{background:linear-gradient(135deg,#CF6C78 0%,#8B5E5E 100%);color:#fff;text-align:center;padding:3rem 1.5rem 2.5rem;margin:-3rem -1.5rem 2.5rem;border-radius:0 0 2rem 2rem;}'
  + '.abrigo-hero h1{font-family:var(--font-heading);font-size:2.2rem;margin-bottom:0.5rem;}'
  + '.abrigo-hero p{opacity:0.9;max-width:480px;margin:0 auto 1.5rem;}'
  + '.abrigo-hero__stats{display:flex;gap:1.5rem;justify-content:center;flex-wrap:wrap;font-size:0.95rem;opacity:0.92;}'
  + '.abrigo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:1.25rem;}'
  + '.abrigo-card{background:#fff;border-radius:var(--radius-card);box-shadow:var(--shadow-card);overflow:hidden;transition:transform var(--transition),box-shadow var(--transition);}'
  + '.abrigo-card:hover{transform:translateY(-4px);box-shadow:0 8px 28px rgba(0,0,0,0.13);}'
  + '.abrigo-card__media{position:relative;}'
  + '.abrigo-card img,.abrigo-placeholder{width:100%;aspect-ratio:1/1;object-fit:cover;background:var(--color-accent);display:flex;align-items:center;justify-content:center;font-size:3.5rem;}'
  + '.abrigo-card--memorial img{filter:grayscale(100%);}'
  + '.abrigo-status{position:absolute;top:0.5rem;right:0.5rem;padding:0.2rem 0.55rem;border-radius:var(--radius-pill);font-size:0.7rem;font-weight:700;color:#fff;}'
  + '.s-disponivel{background:#16a34a;}'
  + '.s-reservado{background:#d97706;}'
  + '.s-em_tratamento{background:#2563eb;}'
  + '.s-adotado{background:var(--color-primary);}'
  + '.s-obito{background:#6b7280;}'
  + '.abrigo-card__body{padding:0.85rem 1rem;}'
  + '.abrigo-pill{display:inline-block;padding:0.15rem 0.55rem;border-radius:var(--radius-pill);font-size:0.72rem;font-weight:700;background:var(--color-accent);color:var(--color-dark);}'
  + '.abrigo-filters{margin-bottom:0.75rem;}'
  + '.abrigo-filter-row{display:flex;gap:0.4rem;flex-wrap:wrap;margin-bottom:0.4rem;}'
  + '.abrigo-filter-label{font-size:0.75rem;color:var(--color-muted);text-transform:uppercase;letter-spacing:0.06em;align-self:center;margin-right:0.25rem;}'
  + '.abrigo-back{display:inline-block;margin-bottom:1.5rem;color:var(--color-muted);font-size:0.9rem;}'
  + '.abrigo-detalhe{display:grid;grid-template-columns:1fr 1fr;gap:2.5rem;align-items:start;}'
  + '.abrigo-detalhe img{width:100%;aspect-ratio:1/1;object-fit:cover;border-radius:var(--radius-card);}'
  + '.abrigo-info-table td{padding:0.4rem 0;vertical-align:top;}'
  + '.abrigo-info-table td:first-child{color:var(--color-muted);width:38%;}'
  + '.abrigo-cta{background:var(--color-accent);border-radius:var(--radius-card);padding:1.5rem;margin-top:1rem;}'
  + '.abrigo-memorial summary{cursor:pointer;font-size:1rem;font-weight:600;color:var(--color-muted);padding:1rem 0;list-style:none;}'
  + '.abrigo-memorial summary::-webkit-details-marker{display:none;}'
  + '.abrigo-memorial summary::before{content:"+ ";}'
  + 'details.abrigo-memorial[open] summary::before{content:"- ";}'
  + '.btn--filter{padding:0.35rem 0.85rem;border-radius:var(--radius-pill);font-size:0.8rem;font-weight:600;border:2px solid var(--color-border);color:var(--color-text);background:#fff;text-decoration:none;}'
  + '.btn--filter.active,.btn--filter:hover{border-color:var(--color-primary);color:var(--color-primary);background:#fff8f8;}'
  + '@media(max-width:640px){.abrigo-detalhe{grid-template-columns:1fr;}.abrigo-hero h1{font-size:1.7rem;}}'
  + '</style>';

function abrigoPage(title, bodyHtml) {
  return PAGE_SHELL_HEAD
    + '<title>' + escHtml(title) + ' - Amah Cats</title></head><body>'
    + '<header class="header header--scrolled" style="position:sticky;top:0;z-index:100;">'
    + '<a href="/" class="header__logo"><img src="/assets/amahcats_logo.png" alt="Amah Cats"></a>'
    + '<nav class="header__nav"><a href="/#adocao">Adotar</a><a href="/animais" style="font-weight:700;">Animais</a></nav>'
    + '</header>'
    + '<main id="main-content" style="padding:3rem 0 5rem;"><div class="container">'
    + bodyHtml
    + '</div></main>'
    + '<footer style="text-align:center;padding:2rem;color:var(--color-muted);font-size:0.85rem;">'
    + '&copy; ' + new Date().getFullYear() + ' Amah Cats &mdash; Adocao responsavel'
    + '</footer></body></html>';
}

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

var STATUS_INFO = {
  disponivel:    { label: 'Disponivel',    cls: 's-disponivel' },
  reservado:     { label: 'Reservado',     cls: 's-reservado' },
  em_tratamento: { label: 'Em Tratamento', cls: 's-em_tratamento' },
  adotado:       { label: 'Adotado',       cls: 's-adotado' },
  obito:         { label: 'Estrela',       cls: 's-obito' },
};

function buildCard(a, isMemorial) {
  var speciesLabel = a.species === 'gato' ? 'Gato' : a.species === 'cachorro' ? 'Cachorro' : 'Outro';
  var si = STATUS_INFO[a.status] || { label: a.status, cls: 's-obito' };
  var imgEl = a.cover_photo
    ? '<img src="/animal-foto/' + escHtml(path.basename(a.cover_photo)) + '" alt="Foto de ' + escHtml(a.name) + '" loading="lazy">'
    : '<div class="abrigo-placeholder" style="background:var(--color-accent);display:flex;align-items:center;justify-content:center;font-size:3.5rem;">' + (a.species === 'gato' ? '🐱' : '🐶') + '</div>';
  var memorialExtra = isMemorial ? ' abrigo-card--memorial' : '';
  var starBadge = isMemorial ? '<span style="position:absolute;top:0.5rem;left:0.5rem;font-size:1.1rem;" title="Virou estrelinha">🌟</span>' : '';
  return '<a href="/animais/' + escHtml(a.slug) + '" style="text-decoration:none;color:inherit;">'
    + '<div class="abrigo-card' + memorialExtra + '">'
    + '<div class="abrigo-card__media">' + imgEl
    + '<span class="abrigo-status ' + si.cls + '">' + si.label + '</span>'
    + starBadge + '</div>'
    + '<div class="abrigo-card__body">'
    + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.2rem;">'
    + '<strong style="font-size:0.95rem;">' + escHtml(a.name) + '</strong>'
    + '<span class="abrigo-pill">' + speciesLabel + '</span>'
    + '</div>'
    + (a.breed ? '<p style="color:var(--color-muted);font-size:0.8rem;margin:0;">' + escHtml(a.breed) + '</p>' : '')
    + (a.birth_approx ? '<p style="color:var(--color-muted);font-size:0.8rem;margin:0;">' + escHtml(a.birth_approx) + '</p>' : '')
    + '</div></div></a>';
}

function filterLink(label, href, active) {
  return '<a href="' + href + '" class="btn--filter' + (active ? ' active' : '') + '">' + label + '</a>';
}

async function handleAnimais(req, res, query) {
  try {
    var species   = (query && query.get('species')) ? query.get('species') : '';
    var statusFlt = (query && query.get('status'))  ? query.get('status')  : '';

    var apiUrl = ABRIGO_API + '/api/animals/public?limit=200'
      + (species ? '&species=' + encodeURIComponent(species) : '');
    var apiRes = await fetch(apiUrl, { signal: AbortSignal.timeout(8000) });
    var json = await apiRes.json();
    var all = (json.success && Array.isArray(json.data)) ? json.data : [];

    // contagens por status (excluindo obito do total principal)
    var counts = {};
    var totalVivos = 0;
    all.forEach(function(a) {
      counts[a.status] = (counts[a.status] || 0) + 1;
      if (a.status !== 'obito') totalVivos++;
    });

    // separar memorial
    var vivos    = all.filter(function(a) { return a.status !== 'obito'; });
    var memorial = all.filter(function(a) { return a.status === 'obito'; });

    // aplicar filtro de status
    var visible = statusFlt ? vivos.filter(function(a) { return a.status === statusFlt; }) : vivos;

    // hero stats
    var nGatos    = all.filter(function(a){ return a.species === 'gato' && a.status !== 'obito'; }).length;
    var nCachorros= all.filter(function(a){ return a.species === 'cachorro' && a.status !== 'obito'; }).length;
    var nAdotados = counts['adotado'] || 0;

    // hero banner
    var heroHtml = '<div class="abrigo-hero">'
      + '<p style="font-size:0.8rem;letter-spacing:0.12em;text-transform:uppercase;opacity:0.8;margin-bottom:0.4rem;">Abrigo Amah Cats</p>'
      + '<h1>Encontre seu companheiro</h1>'
      + '<p>Animais resgatados aguardando um lar com amor e cuidado.</p>'
      + '<div class="abrigo-hero__stats">'
      + (nGatos     ? '<span>🐱 ' + nGatos     + (nGatos === 1 ? ' gato' : ' gatos') + '</span>' : '')
      + (nCachorros ? '<span>🐶 ' + nCachorros + (nCachorros === 1 ? ' cachorro' : ' cachorros') + '</span>' : '')
      + (nAdotados  ? '<span>❤️ ' + nAdotados  + ' adotados</span>' : '')
      + '</div></div>';

    // filtros de especie
    var speciesBase = statusFlt ? '?status=' + encodeURIComponent(statusFlt) : '';
    var speciesQ = function(s) {
      return s ? (speciesBase ? speciesBase + '&species=' + s : '?species=' + s) : speciesBase || '/animais';
    };
    var speciesRow = '<div class="abrigo-filter-row">'
      + '<span class="abrigo-filter-label">Especie</span>'
      + filterLink('Todos', '/animais' + speciesBase, !species)
      + filterLink('🐱 Gatos',    '/animais' + speciesQ('gato'),    species === 'gato')
      + filterLink('🐶 Cachorros','/animais' + speciesQ('cachorro'),species === 'cachorro')
      + '</div>';

    // filtros de status
    var statusBase = species ? '?species=' + encodeURIComponent(species) : '';
    var statusQ = function(st) {
      return st ? (statusBase ? statusBase + '&status=' + st : '?status=' + st) : statusBase || '/animais';
    };
    var statusCounts = [
      { key: '',             label: 'Todos (' + totalVivos + ')' },
      { key: 'disponivel',   label: 'Disponivel (' + (counts['disponivel'] || 0) + ')' },
      { key: 'em_tratamento',label: 'Em Tratamento (' + (counts['em_tratamento'] || 0) + ')' },
      { key: 'reservado',    label: 'Reservado (' + (counts['reservado'] || 0) + ')' },
      { key: 'adotado',      label: 'Adotado (' + (counts['adotado'] || 0) + ')' },
    ].filter(function(x) { return x.key === '' || counts[x.key]; });

    var statusRow = '<div class="abrigo-filter-row">'
      + '<span class="abrigo-filter-label">Status</span>'
      + statusCounts.map(function(x) {
          return filterLink(x.label, '/animais' + statusQ(x.key), statusFlt === x.key);
        }).join('')
      + '</div>';

    var filtersHtml = '<div class="abrigo-filters">' + speciesRow + statusRow + '</div>';

    // grid principal
    var cardsHtml = visible.length === 0
      ? '<p style="color:var(--color-muted);text-align:center;padding:3rem 0;">Nenhum animal neste filtro no momento.</p>'
      : '<div class="abrigo-grid">' + visible.map(function(a){ return buildCard(a, false); }).join('') + '</div>';

    // secao memorial
    var memorialHtml = '';
    if (memorial.length > 0) {
      memorialHtml = '<details class="abrigo-memorial" style="border-top:1px solid var(--color-border);margin-top:3rem;">'
        + '<summary>🌟 Em memoria (' + memorial.length + ') - clique para ver</summary>'
        + '<p style="color:var(--color-muted);font-size:0.85rem;margin-bottom:1rem;">Animais que passaram pelo abrigo e viraram estrelinhas. Suas historias ficam guardadas aqui com carinho.</p>'
        + '<div class="abrigo-grid">' + memorial.map(function(a){ return buildCard(a, true); }).join('') + '</div>'
        + '</details>';
    }

    var bodyHtml = heroHtml + filtersHtml + cardsHtml + memorialHtml;
    var html = abrigoPage('Animais para Adocao', bodyHtml);
    res.writeHead(200, Object.assign({}, SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' }));
    res.end(html);
  } catch (err) {
    console.error('[animais] handleAnimais error:', err.message);
    res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>Servico temporariamente indisponivel</h1>');
  }
}

async function handleAnimalDetalhe(req, res, slug) {
  try {
    var apiRes = await fetch(ABRIGO_API + '/api/animals/public/' + encodeURIComponent(slug), { signal: AbortSignal.timeout(8000) });
    if (apiRes.status === 404) {
      var page404 = require('fs').readFileSync(require('path').join(__dirname, '404.html'));
      res.writeHead(404, Object.assign({}, SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' }));
      return res.end(page404);
    }
    var json = await apiRes.json();
    if (!json.success) throw new Error('API error');
    var a = json.data;

    var speciesLabel = a.species === 'gato' ? 'Gato' : a.species === 'cachorro' ? 'Cachorro' : 'Outro';
    var genderLabel  = a.gender === 'macho' ? 'Macho' : a.gender === 'femea' ? 'Femea' : null;

    var isObito = a.status === 'obito';
    var imgHtml = a.cover_photo
      ? '<img src="/animal-foto/' + escHtml(path.basename(a.cover_photo)) + '" alt="Foto de ' + escHtml(a.name) + '"' + (isObito ? ' style="filter:grayscale(100%);"' : '') + '>'
      : '<div class="abrigo-placeholder" style="border-radius:var(--radius-card);aspect-ratio:1/1;display:flex;align-items:center;justify-content:center;background:var(--color-accent);font-size:5rem;">' + (a.species === 'gato' ? '🐱' : '🐶') + '</div>';

    var tableRows = '';
    if (a.breed)       tableRows += '<tr><td>Raca</td><td>' + escHtml(a.breed) + '</td></tr>';
    if (a.color)       tableRows += '<tr><td>Cor</td><td>' + escHtml(a.color) + '</td></tr>';
    if (a.birth_approx) tableRows += '<tr><td>Idade</td><td>' + escHtml(a.birth_approx) + '</td></tr>';
    if (genderLabel)   tableRows += '<tr><td>Sexo</td><td>' + escHtml(genderLabel) + '</td></tr>';

    var ctaHtml = isObito
      ? '<div class="abrigo-cta" style="background:#f3f4f6;"><p style="font-size:1.2rem;margin-bottom:0.5rem;">🌟 Virou estrelinha</p><p style="font-size:0.9rem;line-height:1.6;color:var(--color-muted);">' + escHtml(a.name) + ' passou pelo nosso abrigo e deixou muita saudade. Sua historia fica guardada aqui com carinho.</p></div>'
      : a.status === 'disponivel'
        ? '<div class="abrigo-cta"><h3 style="margin-bottom:0.5rem;">Quero adotar!</h3><p style="font-size:0.9rem;line-height:1.6;">Entre em contato com o abrigo para iniciar o processo de adocao responsavel.</p><a href="/#adocao" class="btn btn--primary" style="margin-top:1rem;">Falar com o abrigo</a></div>'
        : a.status === 'reservado'
          ? '<div class="abrigo-cta" style="background:#fef3c7;"><p style="font-weight:600;">🔒 Reservado</p><p style="font-size:0.9rem;">Este animal ja tem adocao em andamento. Veja outros animais disponiveis!</p><a href="/animais" class="btn btn--filter active" style="margin-top:0.75rem;">Ver outros animais</a></div>'
          : a.status === 'adotado'
            ? '<div class="abrigo-cta" style="background:#fce7f3;"><p style="font-weight:600;">❤️ Adotado!</p><p style="font-size:0.9rem;">Este animal ja encontrou seu lar. Que historia bonita! Veja quem ainda espera por voce.</p><a href="/animais" class="btn btn--filter active" style="margin-top:0.75rem;">Ver disponiveis</a></div>'
            : '';

    var infoHtml = '<a href="/animais" class="abrigo-back">&#8592; Voltar ao catalogo</a>'
      + '<div class="abrigo-detalhe">'
      + imgHtml
      + '<div>'
      + '<h1 style="margin-bottom:0.75rem;">' + escHtml(a.name) + '</h1>'
      + '<div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:1rem;">'
      + '<span class="abrigo-pill">' + escHtml(speciesLabel) + '</span>'
      + '</div>'
      + (tableRows ? '<table class="abrigo-info-table" style="margin-bottom:1rem;width:100%;"><tbody>' + tableRows + '</tbody></table>' : '')
      + (a.personality ? '<h3 style="margin-bottom:0.4rem;">Personalidade</h3><p style="line-height:1.7;margin-bottom:1rem;">' + escHtml(a.personality) + '</p>' : '')
      + (a.history ? '<h3 style="margin-bottom:0.4rem;">Historia</h3><p style="line-height:1.7;margin-bottom:1rem;">' + escHtml(a.history) + '</p>' : '')
      + ctaHtml
      + '</div></div>';

    var html = abrigoPage(a.name, infoHtml);
    res.writeHead(200, Object.assign({}, SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' }));
    res.end(html);
  } catch (err) {
    console.error('[animais] handleAnimalDetalhe error:', err.message);
    res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>Servico temporariamente indisponivel</h1>');
  }
}

function handleAdocao(req, res, clientIp) {
  if (isAdoptRateLimited(clientIp)) {
    sendJson(res, 429, { success: false, message: 'Muitas tentativas. Tente novamente em 1 minuto.' });
    return;
  }

  var chunks = [];
  var totalSize = 0;

  req.on('data', function(chunk) {
    totalSize += chunk.length;
    if (totalSize > BODY_LIMIT) {
      req.destroy();
      sendJson(res, 413, { success: false, message: 'Payload muito grande.' });
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', async function() {
    if (res.writableEnded) return;

    var data;
    try {
      data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      sendJson(res, 400, { success: false, message: 'JSON inválido.' });
      return;
    }

    var turnstileToken = (data['cf-turnstile-response'] || '');
    var turnstileValid = await verifyTurnstile(turnstileToken, clientIp);
    if (!turnstileValid) {
      sendJson(res, 403, { success: false, message: 'Verificação de segurança falhou. Recarregue a página e tente novamente.' });
      return;
    }

    var nome = (data.nome || '').trim().slice(0, 255);
    var email = (data.email || '').trim().slice(0, 254);
    var telefone = (data.telefone || '').trim().replace(/\D/g, '').slice(0, 15);
    var especie = (data.especie || '').trim().slice(0, 50);
    var mensagem = (data.mensagem || '').trim().slice(0, 2000);
    var comoConheceu = (data.como_conheceu || '').trim().slice(0, 100);

    if (!nome || !email || !telefone) {
      sendJson(res, 400, { success: false, message: 'Preencha todos os campos obrigatórios.' });
      return;
    }

    if (!EMAIL_REGEX.test(email)) {
      sendJson(res, 400, { success: false, message: 'E-mail inválido.' });
      return;
    }

    if (!isValidBRPhone(telefone)) {
      sendJson(res, 400, { success: false, message: 'Telefone inválido.' });
      return;
    }

    // AmahCats: default gatos
    if (!especie) especie = 'gatos';

    try {
      var result = await forwardToIntake({
        nome, email, telefone, especie, mensagem,
        clientIp: clientIp,
        clientUa: req.headers['user-agent'] || '',
        howFound: comoConheceu,
      });
      console.info('[' + localTimestamp() + '] ADOCAO->LATE id=' + ((result.data && result.data.contact_id) || 'ok') + ' email="' + email + '" tel="' + telefone + '"');
      sendJson(res, 200, { success: true, message: 'Interesse registrado com sucesso!' });
    } catch (err) {
      console.error('[' + localTimestamp() + '] ADOCAO->LATE ERRO: status=' + (err.statusCode || '?') + ' code=' + (err.errorCode || '-') + ' msg="' + err.message + '"');

      if (err.errorCode === 'IDENTITY_CONFLICT') {
        sendIdentityConflictAlert({
          nome, email: maskEmail(email), telefone: maskPhone(telefone), especie,
          clientIp, statusCode: err.statusCode, message: err.message,
        });
        sendJson(res, 409, {
          success: false,
          message: 'Detectamos um conflito no seu cadastro. Entre em contato pelo Instagram para regularizar.',
        });
        return;
      }

      if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
        var body422 = { success: false, message: err.userMessage || 'Dados inválidos. Verifique os campos e tente novamente.' };
        if (err.field) body422.field = err.field;
        sendJson(res, err.statusCode, body422);
        return;
      }

      saveContingencyJson({
        timestamp: new Date().toISOString(), form: 'adocao',
        nome, email: maskEmail(email), telefone: maskPhone(telefone),
        especie, mensagem: (mensagem || '').slice(0, 500),
        error: err.message,
      });
      sendContingencyAlert({
        nome, email: maskEmail(email), telefone: maskPhone(telefone),
        especie, error: err.message,
      });

      sendJson(res, 200, {
        success: true, pending: true,
        message: 'Recebemos seu interesse! Entraremos em contato em breve.',
      });
    }
  });

  req.on('error', function() {
    if (!res.writableEnded) {
      sendJson(res, 500, { success: false, message: 'Erro ao processar.' });
    }
  });
}

// ---------- CPF validation ----------
function isValidCpf(raw) {
  var digits = String(raw || '').replace(/\D/g, '');
  if (digits.length !== 11) return false;
  if (/^(.)\1{10}$/.test(digits)) return false;

  var sum1 = 0;
  for (var i = 0; i < 9; i++) sum1 += parseInt(digits[i]) * (10 - i);
  var r1 = (sum1 * 10) % 11;
  if (r1 === 10 || r1 === 11) r1 = 0;
  if (r1 !== parseInt(digits[9])) return false;

  var sum2 = 0;
  for (var j = 0; j < 10; j++) sum2 += parseInt(digits[j]) * (11 - j);
  var r2 = (sum2 * 10) % 11;
  if (r2 === 10 || r2 === 11) r2 = 0;
  return r2 === parseInt(digits[10]);
}

function handleEntrevista(req, res, clientIp) {
  if (isAdoptRateLimited(clientIp)) {
    sendJson(res, 429, { success: false, message: 'Muitas tentativas. Tente novamente em 1 minuto.' });
    return;
  }

  var chunks = [];
  var totalSize = 0;

  req.on('data', function(chunk) {
    totalSize += chunk.length;
    if (totalSize > BODY_LIMIT) {
      req.destroy();
      sendJson(res, 413, { success: false, message: 'Payload muito grande.' });
      return;
    }
    chunks.push(chunk);
  });

  req.on('end', async function() {
    if (res.writableEnded) return;

    var data;
    try {
      data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      sendJson(res, 400, { success: false, message: 'JSON inválido.' });
      return;
    }

    var step = data.step || 1;
    var fields = data.data || data;
    var opportunityId = data.opportunity_id || null;
    var opportunitySig = data.opportunity_sig || null;

    if (step < 1 || step > 4 || !Number.isInteger(step)) {
      sendJson(res, 400, { success: false, message: 'Step inválido.' });
      return;
    }

    // Verificar Turnstile no step final (step 4 = panel 3)
    if (step === 4) {
      var turnstileToken = (data['cf-turnstile-response'] || '');
      var turnstileValid = await verifyTurnstile(turnstileToken, clientIp);
      if (!turnstileValid) {
        sendJson(res, 403, { success: false, message: 'Verificação de segurança falhou. Recarregue a página e tente novamente.' });
        return;
      }
    }

    if (step === 1) {
      await handleEntrevistaStep1(res, fields, clientIp, req);
    } else {
      await handleEntrevistaStepN(res, step, fields, opportunityId, opportunitySig);
    }
  });

  req.on('error', function() {
    if (!res.writableEnded) {
      sendJson(res, 500, { success: false, message: 'Erro ao processar.' });
    }
  });
}

async function handleEntrevistaStep1(res, fields, clientIp, req) {
  var nomeCompleto = (fields.nome_completo || '').trim().slice(0, 255);
  var cpf = (fields.cpf || '').trim().replace(/\D/g, '').slice(0, 11);
  var email = (fields.email_form || fields.email || '').trim().slice(0, 254);
  var telefone = (fields.telefone_form || fields.telefone || '').trim().replace(/\D/g, '').slice(0, 15);

  if (!nomeCompleto) {
    sendJson(res, 400, { success: false, message: 'Nome completo é obrigatório.' });
    return;
  }

  if (!cpf) {
    sendJson(res, 400, { success: false, message: 'CPF é obrigatório.' });
    return;
  }

  if (!isValidCpf(cpf)) {
    sendJson(res, 400, { success: false, message: 'CPF inválido.' });
    return;
  }

  if (!email) {
    sendJson(res, 400, { success: false, message: 'E-mail é obrigatório.' });
    return;
  }

  if (!EMAIL_REGEX.test(email)) {
    sendJson(res, 400, { success: false, message: 'E-mail inválido.' });
    return;
  }

  if (!telefone) {
    sendJson(res, 400, { success: false, message: 'Telefone é obrigatório.' });
    return;
  }

  if (telefone.length < 10) {
    sendJson(res, 400, { success: false, message: 'Telefone inválido.' });
    return;
  }

  var nomeSocial = (fields.nome_social || '').trim().slice(0, 255);
  var rg = (fields.rg || '').trim().slice(0, 20);
  var dataNascimento = (fields.data_nascimento || '').trim().slice(0, 20);
  var estadoCivil = (fields.estado_civil || '').trim().slice(0, 50);
  var profissao = (fields.profissao || '').trim().slice(0, 255);
  var facebookInstagram = (fields.facebook_instagram || '').trim().slice(0, 255);
  var tipoAnimal = (fields.tipo_animal || '').trim().slice(0, 50);
  var comoConheceu = (fields.como_conheceu || '').trim().slice(0, 100);
  var cep = (fields.cep || '').trim().slice(0, 10);
  var rua = (fields.rua || '').trim().slice(0, 255);
  var numero = (fields.numero || '').trim().slice(0, 20);
  var bairro = (fields.bairro || '').trim().slice(0, 100);
  var complemento = (fields.complemento || '').trim().slice(0, 100);
  var cidade = (fields.cidade || '').trim().slice(0, 100);
  var uf = (fields.uf || '').trim().slice(0, 2);

  var payload = {
    name: nomeCompleto,
    email: email,
    phone: normalizePhoneBR(telefone),
    cpf: cpf,
    client_ip: clientIp,
    client_ua: req.headers['user-agent'] || '',
  };

  if (nomeSocial) payload.nome_social = nomeSocial;
  if (rg) payload.rg = rg;
  if (dataNascimento) payload.birth_date = dataNascimento;
  if (estadoCivil) payload.estado_civil = estadoCivil;
  if (profissao) payload.profissao = profissao;
  if (facebookInstagram) payload.redes_sociais = facebookInstagram;
  // AmahCats: default gatos (sem tipo_animal no formulario)
  var SPECIES_MAP = { cachorro: 'cães', gato: 'gatos' };
  payload.species_preference = SPECIES_MAP[tipoAnimal] || tipoAnimal || 'gatos';
  payload.how_found = comoConheceu || undefined;
  payload.intake_source = 'amahcats';

  if (cep || rua || numero || bairro || cidade || uf) {
    payload.endereco = { cep: cep, rua: rua, numero: numero, bairro: bairro, complemento: complemento, cidade: cidade, uf: uf };
  }

  try {
    var response = await fetch(CRM_INTAKE_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-intake-token': CRM_INTAKE_TOKEN,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });

    var result = await response.json();
    if (!response.ok) {
      var crmErr = new Error(result.error || 'CRM intake HTTP ' + response.status);
      crmErr.statusCode = response.status;
      crmErr.userMessage = result.error || null;
      crmErr.field = result.field || null;
      throw crmErr;
    }

    var oppId = result.data && result.data.opportunity_id;
    var oppSig = oppId
      ? crypto.createHmac('sha256', OPPORTUNITY_HMAC_SECRET).update(oppId).digest('hex')
      : undefined;
    console.info('[' + localTimestamp() + '] ENTREVISTA step1->LATE opp=' + (oppId || 'ok') + ' email="' + email + '" tel="' + telefone + '"');
    sendJson(res, 200, { success: true, message: 'Dados pessoais salvos!', opportunity_id: oppId, opportunity_sig: oppSig });
  } catch (err) {
    console.error('[' + localTimestamp() + '] ENTREVISTA step1->LATE ERRO: ' + err.message);
    if (err.statusCode && err.statusCode >= 400 && err.statusCode < 500) {
      var body = { success: false, message: err.userMessage || 'Dados inválidos. Verifique os campos e tente novamente.' };
      if (err.field) body.field = err.field;
      sendJson(res, err.statusCode, body);
      return;
    }
    sendJson(res, 500, { success: false, message: 'Erro ao salvar dados pessoais. Tente novamente.' });
  }
}

// Mapeia nomes do formulario HTML para nomes canonicos dos custom fields no LATE
var FIELD_RENAME = { raca: 'raca_interesse', animais_quais: 'quais_animais' };
var FIELD_STRIP = { tipo_animal: true, consent: true, consent_form: true, 'cf-turnstile-response': true, como_conheceu: true };

async function handleEntrevistaStepN(res, step, fields, opportunityId, opportunitySig) {
  if (!opportunityId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(opportunityId)) {
    sendJson(res, 400, { success: false, message: 'ID de oportunidade inválido.' });
    return;
  }

  if (!opportunitySig || typeof opportunitySig !== 'string' || !/^[0-9a-f]{64}$/i.test(opportunitySig)) {
    sendJson(res, 403, { success: false, message: 'Assinatura inválida.' });
    return;
  }
  var expectedSig = crypto.createHmac('sha256', OPPORTUNITY_HMAC_SECRET).update(opportunityId).digest('hex');
  var sigBuffer = Buffer.from(opportunitySig, 'hex');
  var expectedBuffer = Buffer.from(expectedSig, 'hex');
  if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    sendJson(res, 403, { success: false, message: 'Assinatura inválida.' });
    return;
  }
  var url = CRM_INTAKE_URL.replace('/intake/iacd', '/intake/iacd/' + opportunityId + '/fields');

  var mapped = {};
  Object.keys(fields).forEach(function(k) {
    if (FIELD_STRIP[k]) return;
    var key = FIELD_RENAME[k] || k;
    mapped[key] = fields[k];
  });

  try {
    var response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'x-intake-token': CRM_INTAKE_TOKEN,
      },
      body: JSON.stringify({ step: step, fields: mapped }),
      signal: AbortSignal.timeout(5000),
    });

    var result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || 'CRM fields HTTP ' + response.status);
    }

    console.info('[' + localTimestamp() + '] ENTREVISTA step' + step + '->LATE opp=' + opportunityId + ' ok');
    var message = step === 4 ? 'Formulário enviado com sucesso!' : 'Dados salvos!';
    sendJson(res, 200, { success: true, message: message });
  } catch (err) {
    console.error('[' + localTimestamp() + '] ENTREVISTA step' + step + '->LATE ERRO: ' + err.message);
    if (step === 4) {
      sendJson(res, 500, { success: false, message: 'Erro ao enviar formulário. Tente novamente.' });
    } else {
      saveContingencyJson({
        timestamp: new Date().toISOString(), form: 'entrevista',
        step: step, opportunity_id: opportunityId,
        fields: mapped, error: err.message,
      });
      sendContingencyAlert({
        nome: 'Step ' + step + ' (opp ' + opportunityId + ')',
        email: '', telefone: '', especie: '',
        error: 'Falha no step ' + step + ': ' + err.message,
      });
      sendJson(res, 200, {
        success: true, pending: true,
        message: 'Dados recebidos. Processamento pode levar alguns minutos.',
      });
    }
  }
}

// ---------- Tokens assinados para pre-preenchimento ----------
function createSignedToken(contactId, ttlMinutes) {
  var expiry = Date.now() + (ttlMinutes * 60 * 1000);
  var payload = contactId + ':' + expiry;
  var sig = crypto.createHmac('sha256', PREFILL_TOKEN_SECRET)
    .update(payload).digest('hex');
  return Buffer.from(payload).toString('base64url') + '.' + sig;
}

function verifySignedToken(token) {
  if (!token || typeof token !== 'string') return null;
  var parts = token.split('.');
  if (parts.length !== 2) return null;
  var payloadStr;
  try {
    payloadStr = Buffer.from(parts[0], 'base64url').toString();
  } catch { return null; }
  var sig = parts[1];
  if (!sig || !/^[0-9a-f]{64}$/i.test(sig)) return null;
  var expected = crypto.createHmac('sha256', PREFILL_TOKEN_SECRET)
    .update(payloadStr).digest('hex');
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
  var segments = payloadStr.split(':');
  if (segments.length !== 2) return null;
  var contactId = segments[0];
  var expiry = parseInt(segments[1], 10);
  if (Date.now() > expiry) return null;
  return contactId;
}

var usedTokens = new Map();
setInterval(function() {
  var now = Date.now();
  usedTokens.forEach(function(val, key) {
    if (now > val.expiresAt) usedTokens.delete(key);
  });
}, 5 * 60 * 1000);

async function handleContatoPreview(req, res, clientIp) {
  var url = new URL(req.url, 'http://localhost');
  var token = url.searchParams.get('t');

  if (!token) {
    sendJson(res, 400, { success: false, message: 'Token obrigatório' });
    return;
  }

  var contactId = verifySignedToken(token);
  var isSignedToken = !!contactId;

  if (!contactId) {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
      contactId = token;
    } else {
      sendJson(res, 403, { success: false, message: 'Token inválido ou expirado.' });
      return;
    }
  }

  if (isSignedToken) {
    var tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    var usage = usedTokens.get(tokenHash);
    if (usage && usage.count >= 3) {
      sendJson(res, 403, { success: false, message: 'Token ja utilizado.' });
      return;
    }
    usedTokens.set(tokenHash, {
      count: (usage ? usage.count : 0) + 1,
      expiresAt: Date.now() + (30 * 60 * 1000),
    });
  }

  try {
    var contactUrl = CRM_INTAKE_URL.replace('/intake/iacd', '/contatos/' + encodeURIComponent(contactId));
    var response = await fetch(contactUrl, {
      method: 'GET',
      headers: {
        'x-intake-token': CRM_INTAKE_TOKEN,
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      sendJson(res, 404, { success: false, message: 'Contato nao encontrado' });
      return;
    }

    var result = await response.json();
    var contact = (result && result.data) || result || {};
    sendJson(res, 200, {
      success: true,
      data: {
        nome: contact.name || contact.nome || '',
        email: contact.email || '',
        telefone: contact.phone || contact.telefone || '',
      },
    });
  } catch (err) {
    console.error('[' + localTimestamp() + '] CONTATO-PREVIEW ERRO: ' + err.message);
    sendJson(res, 404, { success: false, message: 'Contato nao encontrado' });
  }
}

// ---------- Servidor ----------
const server = http.createServer((req, res) => {
  var clientIp = getClientIp(req);

  // Redirect www -> canonical
  var host = (req.headers.host || '').split(':')[0].toLowerCase();
  if (SECONDARY_DOMAINS.includes(host)) {
    res.writeHead(301, { Location: 'https://' + CANONICAL_DOMAIN + req.url });
    return res.end();
  }

  var parsedUrl;
  try {
    parsedUrl = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end('Bad Request');
  }
  var pathname;
  try {
    pathname = decodeURIComponent(parsedUrl.pathname).replace(/\/+$/, '') || '/';
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    return res.end('Bad Request');
  }

  // Scanner detection
  var flags = {
    isScanner: isScannerPath(pathname),
    isNoisy404: isNoisy404Path(pathname),
  };

  if (flags.isScanner) {
    console.warn(`[${new Date().toISOString()}] 403 scanner method=${req.method} path=${pathname} ip=${clientIp} ua="${(req.headers['user-agent'] || '-').slice(0, 80)}"`);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden');
  }

  // Rate limiting
  var bucket = getRateLimitBucket(pathname, flags);
  if (isRateLimited(bucket, clientIp)) {
    res.writeHead(429, { 'Content-Type': 'text/plain', 'Retry-After': '60' });
    return res.end('Too Many Requests');
  }

  // GET /animal-foto/:filename — proxy de fotos do abrigo (evita CORP cross-origin)
  if (req.method === 'GET' && pathname.startsWith('/animal-foto/')) {
    var filename = path.basename(pathname);
    if (/^[a-zA-Z0-9_\-]+\.(jpg|jpeg|png|webp|gif)$/i.test(filename)) {
      var proxyReq = require('http').request(
        { host: '192.168.0.125', port: 3200, path: '/uploads/animals/' + filename, method: 'GET' },
        function(proxyRes) {
          var ct = proxyRes.headers['content-type'] || 'image/jpeg';
          res.writeHead(proxyRes.statusCode, {
            'Content-Type': ct,
            'Cache-Control': 'public, max-age=86400',
            'X-Robots-Tag': 'noindex',
          });
          proxyRes.pipe(res);
        }
      );
      proxyReq.on('error', function() {
        res.writeHead(502); res.end();
      });
      proxyReq.end();
      return;
    }
  }

  // GET /animais — catalogo publico de adocao (late-abrigo)
  if (req.method === 'GET' && pathname === '/animais') {
    handleAnimais(req, res, parsedUrl.searchParams);
    return;
  }

  // GET /animais/:slug — ficha publica do animal
  if (req.method === 'GET' && pathname.startsWith('/animais/')) {
    var slug = pathname.slice('/animais/'.length).replace(/[^a-z0-9-]/gi, '');
    if (slug) { handleAnimalDetalhe(req, res, slug); return; }
  }

  // POST /api/adocao
  if (req.method === 'POST' && pathname === '/api/adocao') {
    handleAdocao(req, res, clientIp);
    return;
  }

  // POST /api/entrevista
  if (req.method === 'POST' && pathname === '/api/entrevista') {
    handleEntrevista(req, res, clientIp);
    return;
  }

  // GET /api/contato-preview
  if (req.method === 'GET' && pathname === '/api/contato-preview') {
    if (isAdoptRateLimited(clientIp)) {
      sendJson(res, 429, { success: false, message: 'Muitas tentativas. Tente novamente em 1 minuto.' });
      return;
    }
    handleContatoPreview(req, res, clientIp);
    return;
  }

  // Apenas GET/HEAD para demais rotas
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    return res.end('Method Not Allowed');
  }

  if (isBlockedInternalPath(pathname)) {
    var page404 = path.join(PUBLIC_DIR, '404.html');
    fs.readFile(page404, function(err404, data404) {
      var headers = Object.assign({}, SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' });
      if (err404) {
        res.writeHead(404, headers);
        return res.end('<h1>404</h1>');
      }
      res.writeHead(404, headers);
      res.end(data404);
    });
    return;
  }

  // Resolver arquivo
  var publicPath = resolvePublicFilePath(pathname);
  if (!publicPath) {
    var page404 = path.join(PUBLIC_DIR, '404.html');
    fs.readFile(page404, function(err404, data404) {
      var headers = Object.assign({}, SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' });
      if (err404) {
        res.writeHead(404, headers);
        return res.end('<h1>404</h1>');
      }
      res.writeHead(404, headers);
      res.end(data404);
    });
    return;
  }
  var filePath = path.join(PUBLIC_DIR, publicPath);

  // Prevenir directory traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden');
  }

  var ext = path.extname(filePath).toLowerCase();
  var contentType = mimeTypes[ext] || 'application/octet-stream';

  fs.readFile(filePath, function(err, data) {
    if (err) {
      if (!flags.isNoisy404) {
        console.warn('[' + localTimestamp() + '] 404 ' + req.method + ' ' + pathname + ' ip=' + clientIp);
      }
      var page404 = path.join(PUBLIC_DIR, '404.html');
      fs.readFile(page404, function(err404, data404) {
        var headers = Object.assign({}, SECURITY_HEADERS, { 'Content-Type': 'text/html; charset=utf-8' });
        if (err404) {
          res.writeHead(404, headers);
          return res.end('<h1>404</h1>');
        }
        res.writeHead(404, headers);
        res.end(data404);
      });
      return;
    }

    var headers = Object.assign({}, SECURITY_HEADERS, { 'Content-Type': contentType });

    // Cache: imagens 1 ano, CSS/JS 1 hora, HTML sem cache
    if (pathname.startsWith('/assets/') && /\.(jpg|png|webp|svg|ico|woff2?)$/i.test(pathname)) {
      headers['Cache-Control'] = 'public, max-age=31536000, immutable';
    } else if (isAssetPath(pathname)) {
      headers['Cache-Control'] = 'public, max-age=3600, must-revalidate';
    } else {
      headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
    }

    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' ? undefined : data);
  });
});

// Fail-fast: secrets obrigatorios para seguranca dos formularios
if (!OPPORTUNITY_HMAC_SECRET || OPPORTUNITY_HMAC_SECRET.length < 32) {
  console.error('FATAL: OPPORTUNITY_HMAC_SECRET ausente ou muito curta (min. 32 chars). Abortando.');
  process.exit(1);
}
if (!PREFILL_TOKEN_SECRET || PREFILL_TOKEN_SECRET.length < 32) {
  console.error('FATAL: PREFILL_TOKEN_SECRET ausente ou muito curta (min. 32 chars). Abortando.');
  process.exit(1);
}

server.listen(PORT, () => {
  console.info('[' + localTimestamp() + '] amahcats-site rodando na porta ' + PORT);
});
