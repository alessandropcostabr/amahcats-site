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
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

async function forwardToIntake({ nome, email, telefone, especie, mensagem, clientIp, clientUa, source }) {
  var payload = {
    name: nome,
    phone: normalizePhoneBR(telefone) || undefined,
    email: email || undefined,
    species_preference: especie || undefined,
    message: mensagem || undefined,
    client_ip: clientIp || undefined,
    client_ua: clientUa || undefined,
    source: source || 'amahcats',
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
    throw err;
  }
  return result;
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
      sendJson(res, 400, { success: false, message: 'JSON invalido.' });
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

    if (!nome || !email || !telefone) {
      sendJson(res, 400, { success: false, message: 'Preencha todos os campos obrigatorios.' });
      return;
    }

    if (!EMAIL_REGEX.test(email)) {
      sendJson(res, 400, { success: false, message: 'E-mail invalido.' });
      return;
    }

    if (telefone.length < 10) {
      sendJson(res, 400, { success: false, message: 'Telefone invalido.' });
      return;
    }

    // AmahCats: default gatos
    if (!especie) especie = 'gatos';

    try {
      var result = await forwardToIntake({
        nome, email, telefone, especie, mensagem,
        clientIp: clientIp,
        clientUa: req.headers['user-agent'] || '',
        source: 'amahcats',
      });
      console.info('[' + localTimestamp() + '] ADOCAO->LATE id=' + ((result.data && result.data.contact_id) || 'ok') + ' email="' + maskEmail(email) + '"');
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
        sendJson(res, 400, { success: false, message: 'Dados invalidos. Verifique os campos e tente novamente.' });
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
      sendJson(res, 400, { success: false, message: 'JSON invalido.' });
      return;
    }

    var step = data.step || 1;
    var fields = data.data || data;
    var opportunityId = data.opportunity_id || null;
    var opportunitySig = data.opportunity_sig || null;

    if (step < 1 || step > 4 || !Number.isInteger(step)) {
      sendJson(res, 400, { success: false, message: 'Step invalido.' });
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
    sendJson(res, 400, { success: false, message: 'Nome completo e obrigatorio.' });
    return;
  }

  if (!cpf) {
    sendJson(res, 400, { success: false, message: 'CPF e obrigatorio.' });
    return;
  }

  if (!isValidCpf(cpf)) {
    sendJson(res, 400, { success: false, message: 'CPF invalido.' });
    return;
  }

  if (!email) {
    sendJson(res, 400, { success: false, message: 'E-mail e obrigatorio.' });
    return;
  }

  if (!EMAIL_REGEX.test(email)) {
    sendJson(res, 400, { success: false, message: 'E-mail invalido.' });
    return;
  }

  if (!telefone) {
    sendJson(res, 400, { success: false, message: 'Telefone e obrigatorio.' });
    return;
  }

  if (telefone.length < 10) {
    sendJson(res, 400, { success: false, message: 'Telefone invalido.' });
    return;
  }

  var nomeSocial = (fields.nome_social || '').trim().slice(0, 255);
  var rg = (fields.rg || '').trim().slice(0, 20);
  var dataNascimento = (fields.data_nascimento || '').trim().slice(0, 20);
  var estadoCivil = (fields.estado_civil || '').trim().slice(0, 50);
  var profissao = (fields.profissao || '').trim().slice(0, 255);
  var facebookInstagram = (fields.facebook_instagram || '').trim().slice(0, 255);
  var tipoAnimal = (fields.tipo_animal || '').trim().slice(0, 50);
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
    source: 'amahcats',
  };

  if (nomeSocial) payload.nome_social = nomeSocial;
  if (rg) payload.rg = rg;
  if (dataNascimento) payload.birth_date = dataNascimento;
  if (estadoCivil) payload.estado_civil = estadoCivil;
  if (profissao) payload.profissao = profissao;
  if (facebookInstagram) payload.redes_sociais = facebookInstagram;
  // AmahCats: default gatos (sem tipo_animal no formulario)
  var SPECIES_MAP = { cachorro: 'caes', gato: 'gatos' };
  payload.species_preference = SPECIES_MAP[tipoAnimal] || tipoAnimal || 'gatos';

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
      throw new Error(result.error || 'CRM intake HTTP ' + response.status);
    }

    var oppId = result.data && result.data.opportunity_id;
    var oppSig = oppId
      ? crypto.createHmac('sha256', OPPORTUNITY_HMAC_SECRET).update(oppId).digest('hex')
      : undefined;
    console.info('[' + localTimestamp() + '] ENTREVISTA step1->LATE opp=' + (oppId || 'ok') + ' email="' + maskEmail(email) + '"');
    sendJson(res, 200, { success: true, message: 'Dados pessoais salvos!', opportunity_id: oppId, opportunity_sig: oppSig });
  } catch (err) {
    console.error('[' + localTimestamp() + '] ENTREVISTA step1->LATE ERRO: ' + err.message);
    sendJson(res, 500, { success: false, message: 'Erro ao salvar dados pessoais. Tente novamente.' });
  }
}

// Mapeia nomes do formulario HTML para nomes canonicos dos custom fields no LATE
var FIELD_RENAME = { raca: 'raca_interesse', animais_quais: 'quais_animais' };
var FIELD_STRIP = { tipo_animal: true, consent: true, consent_form: true, 'cf-turnstile-response': true };

async function handleEntrevistaStepN(res, step, fields, opportunityId, opportunitySig) {
  if (!opportunityId || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(opportunityId)) {
    sendJson(res, 400, { success: false, message: 'ID de oportunidade invalido.' });
    return;
  }

  if (!opportunitySig || typeof opportunitySig !== 'string' || !/^[0-9a-f]{64}$/i.test(opportunitySig)) {
    sendJson(res, 403, { success: false, message: 'Assinatura invalida.' });
    return;
  }
  var expectedSig = crypto.createHmac('sha256', OPPORTUNITY_HMAC_SECRET).update(opportunityId).digest('hex');
  var sigBuffer = Buffer.from(opportunitySig, 'hex');
  var expectedBuffer = Buffer.from(expectedSig, 'hex');
  if (!crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    sendJson(res, 403, { success: false, message: 'Assinatura invalida.' });
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
      sendJson(res, 500, { success: false, message: 'Erro ao enviar formulario. Tente novamente.' });
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
    sendJson(res, 400, { success: false, message: 'Token obrigatorio' });
    return;
  }

  var contactId = verifySignedToken(token);
  var isSignedToken = !!contactId;

  if (!contactId) {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
      contactId = token;
    } else {
      sendJson(res, 403, { success: false, message: 'Token invalido ou expirado.' });
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
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden');
  }

  // Rate limiting
  var bucket = getRateLimitBucket(pathname, flags);
  if (isRateLimited(bucket, clientIp)) {
    res.writeHead(429, { 'Content-Type': 'text/plain', 'Retry-After': '60' });
    return res.end('Too Many Requests');
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
