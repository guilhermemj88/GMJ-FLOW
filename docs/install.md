# Instalacao do GMJ-FLOW em servidor

Este guia cobre uma instalacao real em Linux usando Docker Compose.

## Requisitos

- Linux com acesso root.
- Git.
- Acesso a internet para instalar Docker, baixar imagens e construir containers.
- Portas liberadas conforme `.env`:
  - `FRONTEND_PORT` padrao `8080/tcp`.
  - `BACKEND_PORT` padrao `8000/tcp`.
  - `CLICKHOUSE_HTTP_PORT` padrao `8123/tcp`.
  - `CLICKHOUSE_NATIVE_PORT` padrao `9000/tcp`.
  - `NETFLOW_PORT` padrao `9995/udp`.
  - Portas UDP extras por sensor quando collectors dinamicos forem aplicados.

## Instalacao nova

Na raiz do projeto:

```sh
sudo ./install.sh
```

O instalador:

- valida que esta em Linux e rodando como root;
- instala Docker se necessario;
- instala o plugin `docker compose` se necessario;
- cria `.env` a partir de `.env.example`;
- gera `GMJFLOW_AUTH_SECRET` quando ainda estiver vazio ou com valor padrao;
- cria `data/backend`, `data/collectors`, `data/backups` e `data/logs`;
- sobe a stack com `docker compose --env-file .env up -d --build`;
- cria o servico `gmj-flow.service` quando systemd estiver disponivel.

Usuario inicial: `admin/admin`. Troque a senha no primeiro login.

## Atualizacao

```sh
sudo scripts/update.sh
```

O script executa `git pull`, recria `backend` e `frontend`, e se `docker-compose.collectors.yml` existir tambem reaplica os collectors dinamicos com `--remove-orphans`.

## Backup

```sh
sudo scripts/backup.sh
```

O arquivo e criado em `data/backups/gmj-flow-<timestamp>.tar.gz`.

Inclui:

- SQLite `data/backend/gmjflow.db`;
- `.env`;
- `data/collectors`;
- `docker-compose.collectors.yml`;
- `clickhouse/init.sql`;
- export logico inicial de `flow_raw` em formato Native quando o container ClickHouse estiver rodando.

O script nao imprime secrets no log. O arquivo `.env` dentro do backup contem secrets e deve ser protegido.

## Restore

```sh
sudo scripts/restore.sh data/backups/gmj-flow-YYYYmmddTHHMMSSZ.tar.gz
```

Digite `RESTORE` para confirmar. O restore cria copias `*.pre-restore-<timestamp>` antes de sobrescrever SQLite, `.env`, collectors e compose de collectors.

Depois reinicie:

```sh
docker compose --env-file .env up -d
```

## Systemd

O instalador cria `gmj-flow.service` quando systemd estiver ativo.

Comandos uteis:

```sh
systemctl status gmj-flow
systemctl restart gmj-flow
journalctl -u gmj-flow
```

## Seguranca

- Altere `GMJFLOW_AUTH_SECRET` somente com a stack parada; tokens antigos serao invalidados.
- Proteja `.env` e `data/backups`.
- `GMJFLOW_ENABLE_COLLECTOR_APPLY=false` e o padrao mais conservador.
- Para aplicar collectors pela interface, o backend monta `./:/app/runtime` e `/var/run/docker.sock:/var/run/docker.sock`. Isso da ao backend poder equivalente a Docker admin no servidor. Habilite apenas em servidor confiavel e com acesso administrativo restrito.

## Desinstalacao

```sh
sudo scripts/uninstall.sh
```

Digite `UNINSTALL` para parar containers. Digite `DELETE DATA` somente se tambem quiser remover volumes Docker e `./data`.
