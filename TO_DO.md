# AMAH Cats — TO DO

## DNS / Cloudflare

### amahcats.com (já no Cloudflare)
- [x] Atualizar nameservers no registrador:
  - `chin.ns.cloudflare.com`
  - `dale.ns.cloudflare.com`
- [x] Adicionar CNAME no Cloudflare apontando para o tunnel
- [ ] Aguardar propagação DNS

### amahcats.com.br (no Cloudflare)
- [x] Concluir pagamento do registro.br
- [x] Atualizar nameservers no registrador:
  - `may.ns.cloudflare.com`
  - `roman.ns.cloudflare.com`
- [x] Adicionar CNAME no Cloudflare apontando para o tunnel
- [ ] Aguardar propagação DNS

### CNAME records (após zones ativarem)
Para cada zone, criar:
```
Tipo: CNAME
Nome: @
Conteúdo: 2c5a19af-95fb-4440-9d17-924c6c298674.cfargotunnel.com
Proxy: ativado (nuvem laranja)

Tipo: CNAME
Nome: www
Conteúdo: 2c5a19af-95fb-4440-9d17-924c6c298674.cfargotunnel.com
Proxy: ativado (nuvem laranja)
```

## Infraestrutura (já feito)
- [x] index.html com logo
- [x] server.js na porta 8083
- [x] ecosystem.config.js (PM2)
- [x] robots.txt (bloqueando indexação)
- [x] Entrada no cloudflared config.yml
- [x] PM2 rodando e salvo
