# Catalogo de Adocao - Design Spec
**Data:** 2026-04-26
**Projeto:** amahcats-site
**Status:** Aprovado pelo usuario

---

## Resumo

Catalogo publico de gatos para adocao no site amahcats.com.br. Cada gato tem uma pagina de historia com timeline de eventos. Admin integrado ao proprio site para gerenciar gatos, fotos e timeline. Integracao com LATE CRM mapeada como Phase 2.

---

## Decisoes de Design

| Decisao | Escolha | Motivo |
|---------|---------|--------|
| Layout do catalogo | Grade de fotos (3 colunas) | Melhor scannabilidade emocional para adocao |
| Estrutura de paginas | /gatos completo + teaser em / | Landing converte, /gatos conta a historia |
| Admin | Integrado ao amahcats-site /admin | Consistente com stack, sem infra nova |
| Base do admin | Copiado/adaptado do amahvet-site | Aproveitar HTML/JS/CSS ja feito |
| Storage | data/gatos.json (modulo lib/gatos.js) | Zero dependencias, consistente com stack |
| Sessoes admin | In-memory Map + crypto nativo | amahvet-site usa PostgreSQL - incompativel |
| Fotos | Upload via admin para assets/gatos/ | Controle total, sem dependencia externa |
| Identificacao | slug gerado do nome + ID interno | URLs legíveis, unicidade garantida |
| LATE bridge | Phase 2 | Catalogo funciona independente primeiro |

---

## Arquitetura

### Novos arquivos

```
amahcats-site/
├── lib/
│   ├── gatos.js           # CRUD do catalogo (ler, salvar, slug, busca)
│   └── gatos-upload.js    # Multipart upload nativo (sem dependencias)
├── data/
│   └── gatos.json         # Banco de dados dos gatos
├── assets/
│   └── gatos/             # Fotos: assets/gatos/<slug>/foto-1.jpg
├── gatos.html             # Pagina publica /gatos (catalogo completo)
├── gato.html              # Pagina publica /gatos/:slug (historia + timeline)
├── admin/
│   ├── index.html         # Dashboard admin (adaptado do amahvet-site)
│   ├── login.html         # Login admin (adaptado do amahvet-site)
│   ├── gatos.html         # Admin: lista + filtros
│   ├── gato-editor.html   # Admin: criar/editar gato + timeline + fotos
│   ├── admin.js           # JS compartilhado do admin
│   └── admin.css          # Estilos admin
└── css/
    └── gatos.css          # Estilos publicos do catalogo
```

### Rotas no server.js

```
# Publicas
GET  /gatos                      → serve gatos.html
GET  /gatos/:slug                → serve gato.html
GET  /api/gatos                  → JSON lista (filtro por status via ?status=)
GET  /api/gatos/:slug            → JSON dados completos do gato

# Admin (requer sessao)
GET  /admin                      → dashboard
GET  /admin/login                → pagina de login
POST /api/admin/login            → autenticar
POST /api/admin/logout           → encerrar sessao
GET  /admin/gatos                → lista admin
GET  /admin/gatos/novo           → editor vazio
GET  /admin/gatos/:slug/editar   → editor preenchido
POST /api/admin/gatos            → criar gato
PUT  /api/admin/gatos/:slug      → atualizar gato
DELETE /api/admin/gatos/:slug    → excluir gato
POST /api/admin/gatos/:slug/timeline        → adicionar evento
DELETE /api/admin/gatos/:slug/timeline/:id  → remover evento
POST /api/admin/gatos/:slug/fotos           → upload foto
DELETE /api/admin/gatos/:slug/fotos/:nome   → remover foto
```

### Autenticacao

- Usuario unico configurado via env: `ADMIN_EMAIL` + `ADMIN_PASSWORD_HASH`
- Hash gerado com `crypto.scryptSync` (mesmo padrao do amahvet-site)
- Sessoes em `Map` na memoria - expira em 24h, reset ao reiniciar PM2 (aceitavel)
- CSRF token por sessao, enviado em header `X-CSRF-Token`
- Cookie `admin_session` HttpOnly + SameSite=Lax + Secure em prod

---

## Modelo de Dados

### gatos.json

```json
{
  "gatos": [
    {
      "id": "uuid-v4",
      "slug": "luna",
      "nome": "Luna",
      "status": "disponivel",
      "sexo": "femea",
      "nascimento_aprox": "2023-06",
      "cor": "branca",
      "personalidade": "Adora colo e ronrona alto",
      "historia": "Luna foi encontrada...",
      "microchip": null,
      "fotos": ["luna/foto-1.jpg", "luna/foto-2.jpg"],
      "foto_capa": "luna/foto-1.jpg",
      "timeline": [
        {
          "id": "uuid",
          "tipo": "resgate",
          "data": "2024-03-10",
          "titulo": "Resgatada",
          "descricao": "Encontrada na Rua das Flores"
        }
      ],
      "informe_adocao": null,
      "late_opp_id": null,
      "late_opp_url": null,
      "criado_em": "2024-03-10T10:00:00Z",
      "atualizado_em": "2024-07-15T14:00:00Z"
    }
  ]
}
```

### Status possiveis

| Valor | Exibicao publica | Cor |
|-------|-----------------|-----|
| `disponivel` | Disponivel | Roxo (#7c3aed) |
| `em_tratamento` | Em tratamento | Amarelo/laranja (#d97706) |
| `adotado` | Adotado | Verde (#059669) |

### Tipos de evento na timeline

| Tipo | Icone | Descricao |
|------|-------|-----------|
| `resgate` | Pata | Data/local do resgate |
| `vacinacao` | Seringa | Vacinas aplicadas |
| `castracao` | Tesoura | Castracao realizada |
| `tratamento` | Cruz | Tratamento medico |
| `entrada_cafe` | Casa | Entrada no Amah Cats |
| `adocao` | Coracao | Adocao finalizada |

### informe_adocao (preenchido quando status = adotado)

```json
{
  "texto": "Luna encontrou sua familia perfeita!",
  "data": "2024-07-15",
  "foto": "luna/adocao.jpg"
}
```

---

## Paginas Publicas

### /gatos - Catalogo completo

- Filtros no topo: Todos | Disponivel | Em tratamento | Adotados
- Grade 3 colunas (2 no mobile)
- Cada card: foto capa + badge de status sobreposto + nome + detalhes rapidos (sexo, idade) + 1 linha de personalidade
- Gatos adotados: exibidos normalmente, inspiram confianca
- Clicar em qualquer card → /gatos/:slug

### /gatos/:slug - Historia do gato

- Foto principal + galeria de miniaturas
- Nome + badge de status
- Descricao de personalidade e historia
- Timeline cronologica com icones por tipo
- Se `adotado`: bloco "Informe de Adocao" (foto + texto celebrativo)
- Se `disponivel`: botao "Quero adotar [nome] →" → /adocao-form.html (Phase 2: ?gato=slug)

### / - Teaser na landing page

- Nova secao "Gatos disponiveis para adocao" inserida apos o formulario de interesse
- Exibe no maximo 3 gatos com status `disponivel` (os mais recentes)
- Botao "Ver todos os gatos →" → /gatos
- Se nao houver gatos disponiveis: secao nao e exibida

---

## Admin

### /admin/login

- Formulario email + senha
- Rate limit 5 tentativas/min por IP
- Redireciona para /admin apos login

### /admin - Dashboard

- Link para gerenciar gatos
- Contagem por status (X disponiveis, Y em tratamento, Z adotados)

### /admin/gatos - Lista

- Tabela: foto capa + nome + status + data atualizacao + acoes
- Filtro por status
- Botao "Novo gato"

### /admin/gatos/:slug/editar - Editor (3 abas)

**Aba Dados:**
- Nome, status, sexo, nascimento aproximado, cor, microchip (opcional)
- Personalidade (1-2 linhas, aparece no card)
- Historia (texto longo, aparece na pagina do gato)

**Aba Fotos:**
- Upload multiplo (max 5MB por foto, jpg/png/webp)
- Definir foto capa
- Reordenar por botoes de seta (cima/baixo) - sem drag-and-drop (evita complexidade)
- Limite de 10 fotos por gato
- Excluir fotos individuais

**Aba Timeline:**
- Lista de eventos em ordem cronologica
- Adicionar evento: tipo + data + titulo + descricao opcional
- Excluir evento
- Quando tipo = `adocao`: formulario de informe aparece (texto + foto opcional)

---

## Phase 2 - Ponte LATE CRM (fora de escopo agora)

Campos reservados no modelo (`null` na Phase 1, usados na Phase 2):
- `late_opp_id` - UUID da oportunidade no LATE
- `late_opp_url` - URL direta para /crm/oportunidades/:id

Fluxo planejado:
1. Botao "Quero adotar" passa `?gato=slug` para /adocao-form.html
2. `/api/entrevista` envia campo `animal_catalogo_slug` ao LATE
3. LATE registra o gato na oportunidade em "Dados do animal"
4. Sincronizacao de status (webhook ou pull - a definir na Phase 2)
5. Quando opp fecha como "Adotado" → atualiza status + informe no catalogo

---

## Seguranca

- Admin protegido por sessao (todas as rotas /admin/* e /api/admin/*)
- CSRF token obrigatorio em POST/PUT/DELETE
- Upload: validar MIME type real (nao so extensao), max 5MB, salvar com nome sanitizado
- Rate limit no login: 5 req/min por IP
- Rotas /admin/* sem sessao: redirecionam para /admin/login (exceto /admin/login em si)
- /api/admin/* sem sessao: retornam 401 JSON
- Fotos servidas como estatico (sem execucao)

---

## Variaveis de Ambiente (novas)

```
ADMIN_EMAIL=admin@amahcats.com.br
ADMIN_PASSWORD_HASH=<gerado via script>
```

Script de setup incluso: `scripts/create-admin.js`
