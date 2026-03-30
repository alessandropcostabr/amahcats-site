const http = require('http');
const fs = require('fs');
const path = require('path');

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
} catch { /* .env ausente — usar variaveis de ambiente do PM2 */ }

const PORT = process.env.PORT || 8083;
const PUBLIC_DIR = __dirname;

// Dominio canonico e dominios secundarios (redirect 301)
const CANONICAL_DOMAIN = 'amahcats.com';
const SECONDARY_DOMAINS = [
  'www.amahcats.com',
  'amahcats.com.br',
  'www.amahcats.com.br',
];

// Mapeamento de rotas para arquivos
const routes = {
  '/': 'index.html',
  '/robots.txt': 'robots.txt',
};

const publicPathResolvers = [
  {
    match: pathname => Object.prototype.hasOwnProperty.call(routes, pathname),
    resolve: pathname => routes[pathname],
  },
  {
    match: pathname => pathname.startsWith('/assets/'),
    resolve: pathname => pathname.slice(1),
  },
];

const blockedInternalPathPatterns = [
  /^\/server\.js$/i,
  /^\/package(?:-lock)?\.json$/i,
  /^\/ecosystem\.config\.js$/i,
  /^\/\.env$/i,
  /^\/node_modules\//i,
];

// Tipos MIME
const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain',
  '.xml': 'application/xml',
  '.webp': 'image/webp',
};

// ---------- Padroes de scanners/bots ----------
const SCANNER_PATTERNS = [
  /^\/\.env/, /^\/\.git/, /^\/\.vscode/, /^\/\.htaccess$/,
  /^\/admin/, /^\/wp-admin/, /^\/wp-login/, /^\/wp-json/,
  /^\/xmlrpc\.php$/, /^\/@vite/, /^\/node_modules/,
  /^\/vendor\//, /^\/src\//, /^\/test/,
  /^\/cgi-bin/, /^\/boaform/, /^\/phpinfo/, /^\/phpmyadmin/i,
  /^\/actuator/, /^\/debug\//, /^\/console/, /^\/backup/, /^\/dump/,
  /~$/, /\.bak$/, /\.swp$/, /\.php$/, /\.sql$/, /\.tar\.gz$/, /\.zip$/,
];

const ENCODED_PATTERNS = [
  /%3A(?:\/\/)/, /^\/https%3A/, /^\/tel%3A/, /^\/mailto%3A/,
];

// ---------- Rate limiting simples (em memoria) ----------
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 60;
const rateLimitMap = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitMap) {
    if (now - entry.start > RATE_LIMIT_WINDOW) rateLimitMap.delete(key);
  }
}, 5 * 60 * 1000);

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimitMap.set(ip, { count: 1, start: now });
    return false;
  }

  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

// ---------- Headers de seguranca ----------
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '0',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
};

// ---------- Utilidades ----------
function localTimestamp() {
  return new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
}

const TRUSTED_PROXY_PREFIXES = [
  '127.', '::1', '::ffff:127.', '192.168.', '10.',
  '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
  '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
  '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
];

function getClientIp(req) {
  const remote = req.socket.remoteAddress || '';
  const isTrustedProxy = TRUSTED_PROXY_PREFIXES.some(prefix => remote.startsWith(prefix));
  if (!isTrustedProxy) return remote || 'unknown';

  const cfIp = (req.headers['cf-connecting-ip'] || '').trim();
  if (cfIp && /^[\d.:a-fA-F]+$/.test(cfIp)) return cfIp;

  const forwarded = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (forwarded && /^[\d.:a-fA-F]+$/.test(forwarded)) return forwarded;

  return remote || 'unknown';
}

function isScannerPath(pathname) {
  return SCANNER_PATTERNS.some(p => p.test(pathname)) ||
         ENCODED_PATTERNS.some(p => p.test(pathname));
}

function resolvePublicFilePath(pathname) {
  for (const resolver of publicPathResolvers) {
    if (resolver.match(pathname)) return resolver.resolve(pathname);
  }
  return null;
}

function isBlockedInternalPath(pathname) {
  return blockedInternalPathPatterns.some(p => p.test(pathname));
}

// ---------- Servidor ----------
const server = http.createServer((req, res) => {
  const clientIp = getClientIp(req);

  // Rate limiting
  if (isRateLimited(clientIp)) {
    res.writeHead(429, { ...SECURITY_HEADERS, 'Retry-After': '60' });
    res.end('Too Many Requests');
    return;
  }

  // Apenas GET e HEAD
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, SECURITY_HEADERS);
    res.end('Method Not Allowed');
    return;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  } catch {
    res.writeHead(400, SECURITY_HEADERS);
    res.end('Bad Request');
    return;
  }

  const pathname = decodeURIComponent(parsedUrl.pathname).replace(/\/+$/, '') || '/';
  const host = (req.headers.host || '').split(':')[0].toLowerCase();

  // Redirect dominios secundarios para canonico
  if (SECONDARY_DOMAINS.includes(host)) {
    res.writeHead(301, {
      ...SECURITY_HEADERS,
      'Location': `https://${CANONICAL_DOMAIN}${pathname}${parsedUrl.search}`,
    });
    res.end();
    return;
  }

  // Scanner/bot — 403 silencioso
  if (isScannerPath(pathname)) {
    res.writeHead(403, SECURITY_HEADERS);
    res.end();
    return;
  }

  // Bloqueio de arquivos internos
  if (isBlockedInternalPath(pathname)) {
    res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>404 — Pagina nao encontrada</h1>');
    return;
  }

  // Resolver arquivo publico
  const relPath = resolvePublicFilePath(pathname);
  if (!relPath) {
    res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<h1>404 — Pagina nao encontrada</h1>');
    return;
  }

  const filePath = path.join(PUBLIC_DIR, relPath);
  const safePath = path.resolve(filePath);
  if (!safePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, SECURITY_HEADERS);
    res.end();
    return;
  }

  fs.readFile(safePath, (err, data) => {
    if (err) {
      res.writeHead(404, { ...SECURITY_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>404 — Pagina nao encontrada</h1>');
      return;
    }

    const ext = path.extname(safePath).toLowerCase();
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    const headers = { ...SECURITY_HEADERS, 'Content-Type': contentType };

    // Cache assets estaticos (1 ano), HTML sem cache
    if (ext !== '.html') {
      headers['Cache-Control'] = 'public, max-age=31536000, immutable';
    } else {
      headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
    }

    res.writeHead(200, headers);
    if (req.method === 'HEAD') {
      res.end();
    } else {
      res.end(data);
    }
  });
});

server.listen(PORT, () => {
  console.error(`[${localTimestamp()}] amahcats-site rodando na porta ${PORT}`);
});
