# GMJ-FLOW — Preview V2 (source canônico)

Source canônico do frontend **V2 (Magic Preview)**. Faz parte do repositório
canônico `GMJ-FLOW` na pasta `preview-v2/`.

## Papel da documentação

- `docs/GMJ-FLOW-V1-V2-MIGRATION.md` (raiz do repo) = **backlog/status canônico** da migração V1 → V2.
- `preview-v2/docs/V2-MIGRATION-MATRIX.md` = **documentação técnica/detalhada da V2** (telas, endpoints, decisões).

## Requisitos

- Node.js 20+ (build validado com Vite 6 / Node 24 no dev e Node 20 no CI).

## Build

```bash
npm ci
npm run build      # gera ./dist
```

O `dist/` **não é versionado** (ver `.gitignore`).

## Runtime atual / publicação

- O preview em `http://172.20.10.40:8081/` é servido por nginx (`gmj-flow-preview`)
  a partir de `/home/guilherme/GMJ-FLOW-preview/dist` (bind mount, read-only).
- A publicação atual é feita **por cópia do artefato `dist`** para esse diretório.
- **Antes de publicar:** gerar backup do `dist` atual (o serviço `:8081` é somente
  leitura e roda contra o backend real; um `dist` quebrado derruba a tela).
- Nesta fase de migração a publicação de novos builds é **manual**.

## Estrutura

```
preview-v2/
  index.html            # template do Vite
  package.json          # scripts: dev | build | preview
  package-lock.json
  vite.config.js        # dev :8081 com proxy /api -> 127.0.0.1:8000
  src/                  # telas .jsx + shared.jsx + CSS
  deploy/               # docker-compose.yml + nginx.conf de referência do preview
  docs/V2-MIGRATION-MATRIX.md
```

## Read-only

O preview roda com **default-deny** para escrita (nginx responde `405` a
POST/PUT/PATCH/DELETE, exceto `login` e consultas de widget). Ações de escrita
aparecem na UI apenas como `ReadOnlyAction` — nunca execute mutações no `:8081`.
