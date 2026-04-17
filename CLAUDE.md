# CLAUDE.md — Amah Cats Site

**ESCRITA:** Nunca usar travessao em respostas, nomes, titulos ou arquivos. Substituir por hifen simples (-) ou virgula (,).

## Visao Geral
Site institucional do cat cafe **Amah Cats** (amahcats.com.br).
Landing page com formulario de adocao + wizard de entrevista multi-step.
Pipeline de adocao integrado ao CRM LATE (mesmo backend do IACD).

## Stack
- **Node.js** v22+ (http nativo, zero dependencias)
- **PM2** via `ecosystem.config.js` (porta **8083**, mode fork)
- **Cloudflare Tunnel** para HTTPS + DNS
- Redirect 301: `www.amahcats.com.br`, `amahcats.com`, `www.amahcats.com`

## Estrutura
```
amahcats-site/
├── server.js              # Servidor HTTP (rotas, rate limit, security headers, API endpoints, CRM)
├── index.html             # Landing page com form1 (interesse em adocao)
├── adocao-form.html       # Wizard de entrevista (4 etapas, ~30 campos, gatos only)
├── privacidade.html       # Politica de privacidade
├── 404.html               # Pagina de erro
├── assets/
│   ├── main.js            # JS da landing (header, menu, form submit)
│   ├── adocao-form.js     # JS do wizard (steps, mascaras, ViaCEP, submit multi-step)
│   └── amahcats_logo.png  # Logo
├── css/
│   ├── style.css          # Design system (tokens, reset, componentes)
│   └── adocao.css         # Estilos do wizard
├── ecosystem.config.js    # PM2 config (gitignored)
├── robots.txt
└── TO_DO.md
```

## Endpoints da API

| Metodo | Rota | Descricao |
|--------|------|-----------|
| `POST` | `/api/adocao` | Form 1 (interesse) - forward para LATE intake |
| `POST` | `/api/entrevista` | Form 2 (wizard) - step 1 cria opp, steps 2-4 atualizam fields |
| `GET` | `/api/contato-preview?t=<token>` | Pre-fill dados do contato via token |

## Convencoes
- CommonJS (`require`/`module.exports`), 2 espacos, semicolons, aspas simples
- Conventional Commits em ingles (`feat:`, `fix:`, `chore:`)
- **NUNCA** commitar `.env` ou `ecosystem.config.js`
- Logs via `console.info`, `console.warn`, `console.error` (nunca `console.log`)
- Identificadores em ingles, mensagens UI em portugues (pt-BR)

## Infra
- **PROD:** DarkStarII (.254), porta 8083
- Cloudflare Tunnel ID: `2c5a19af-95fb-4440-9d17-924c6c298674`
- CRM Backend: LATE PROD em `192.168.0.253:3100` (`/api/crm/intake/iacd`)

## Diferencas do IACD
- Apenas gatos (sem opcao de cachorro no form)
- Kits de adocao: 3 opcoes (sem kit canino)
- Paleta de cores: roxo/rosa (vs marrom/vermelho do IACD)
- `source: 'amahcats'` enviado ao CRM para diferenciar origem
- Default `species_preference: 'gatos'`
- Contingencia salva em `/tmp/amahcats-contingencia/`

## Seguranca
- HMAC secrets obrigatorios (min 32 chars): `OPPORTUNITY_HMAC_SECRET`, `PREFILL_TOKEN_SECRET`
- Rate limiting: 10 req/min por IP para `/api/adocao` e `/api/entrevista`
- Security headers (CSP, HSTS, X-Frame-Options, nosniff)
- Validacao server-side (email, CPF, telefone)
- Scanner detection (bots, .env, .git, wp-admin, etc.)
