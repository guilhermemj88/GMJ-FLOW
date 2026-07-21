# GMJ-FLOW Install

## Instalação simples

```sh
sudo ./scripts/install.sh
```

## Instalação com IA

```sh
sudo ./scripts/install.sh --with-ai --ollama-model qwen2.5:3b-instruct
```

O instalador habilita `AI_MITIGATION_ENABLED=true`, usa `AI_PROVIDER=ollama`, mantém `AI_ALLOW_AUTO=false` e mantém `AI_REQUIRE_POLICY_VALIDATION=true`.

## Instalação com ExaBGP

```sh
sudo ./scripts/install-exabgp.sh \
  --local-as 53194 \
  --peer-as 53194 \
  --local-address 192.168.1.22 \
  --router-id 192.168.1.22 \
  --peer-ip 186.232.160.37 \
  --passive true
```

Se o ExaBGP roda no host e cria `/run/exabgp/exabgp.in` e `/run/exabgp/exabgp.out`,
use o override opcional versionado para montar os pipes no backend:

```sh
docker compose --env-file .env \
  -f docker-compose.yml \
  -f docker-compose.exabgp-pipe.yml \
  --profile ai up -d --build --force-recreate backend frontend
```

Esse override nao e obrigatorio para instalacoes sem ExaBGP no host.

## IA + ExaBGP + autostart

```sh
sudo ./scripts/install.sh --with-ai --with-exabgp --install-systemd
```

## Wizard Web

Acesse `Sistema > Instalação / Setup` para validar Docker, Compose, restart policy, systemd, Ollama, modelo IA, ExaBGP, pipes, nginx resolver, ClickHouse, SQLite e collectors.

Em `Sistema > IA Local`, o operador pode listar modelos, baixar modelo, testar modelo e habilitar/desabilitar IA. A UI não habilita mitigação automática.

## Status BGP / FlowSpec em backend containerizado

Quando o backend roda em container, `systemctl` e `ss` do host podem ficar indisponíveis. Nesse caso:

- Pipe ExaBGP OK significa que o backend consegue escrever no pipe dentro do container.
- Sessão BGP não verificada não significa DOWN.
- FlowSpec não verificado não significa DOWN.
- Para status completo, configure Router SSH no conector BGP ou um Host Agent.

Router SSH para Huawei VRP executa:

```text
display bgp peer
display bgp flow peer
```

Host Agent opcional:

```sh
sudo python3 scripts/host-agent.py --host 172.18.0.1 --port 18080 \
  --log-path /var/log/exabgp-gmj-flow.log \
  --config-path /etc/exabgp/gmj-flow-ne8000.conf
GMJFLOW_HOST_AGENT_URL=http://172.18.0.1:18080
GMJFLOW_EXABGP_LOG_PATH=/var/log/exabgp-gmj-flow.log
GMJFLOW_EXABGP_CONFIG_PATH=/etc/exabgp/gmj-flow-ne8000.conf
```

O agente deve expor `GET /bgp/status?service=<systemd>&peer_ip=<ip>&listen_port=179&log_path=/var/log/exabgp-gmj-flow.log&config_path=/etc/exabgp/gmj-flow-ne8000.conf` retornando JSON com `bgp_state` e `flowspec_state`. Os caminhos aceitos devem coincidir exatamente com os caminhos configurados na inicializacao do agente. O arquivo de configuracao comprova apenas que `ipv4 flow` esta habilitado no bloco `family` do neighbor solicitado; isso nao confirma a instalacao da rota no Huawei.

O backend precisa receber as tres variaveis acima. Preserve o mount existente `/run/exabgp:/run/exabgp`; nao e necessario adicionar mounts para os arquivos do host, pois eles sao lidos somente pelo Host Agent.

O `docker-compose.yml` atual declara o ambiente do backend de forma explicita. Portanto, colocar os valores apenas no `.env` nao os injeta no container ate que o operador adicione, no bloco `backend.environment` da configuracao de producao, os tres mapeamentos abaixo (esta alteracao nao e feita automaticamente):

```yaml
GMJFLOW_HOST_AGENT_URL: "${GMJFLOW_HOST_AGENT_URL-http://172.18.0.1:18080}"
GMJFLOW_EXABGP_LOG_PATH: "${GMJFLOW_EXABGP_LOG_PATH-/var/log/exabgp-gmj-flow.log}"
GMJFLOW_EXABGP_CONFIG_PATH: "${GMJFLOW_EXABGP_CONFIG_PATH-/etc/exabgp/gmj-flow-ne8000.conf}"
```

### Estados e nivel de confirmacao dos anuncios

O registro local e o estado operacional sao informacoes diferentes:

- `pending_approval`: sugestao aguardando o operador; nada foi escrito no pipe.
- `queued`: aprovada e registrada antes da tentativa de envio. Quando `confirmation_level=delivery_attempted`, a intencao de escrita ja foi persistida e o resultado pode estar temporariamente incerto.
- `sent`: o comando foi entregue ao pipe ExaBGP, ainda sem confirmacao operacional.
- `advertised`: o comando foi entregue enquanto a fonte de status configurada informava o peer BGP estabelecido. Este e o unico estado contado como FlowSpec ativo pelo GMJ-FLOW.
- `peer_down`: a tentativa nao foi enviada por indisponibilidade do peer, ou um anuncio antes operacional perdeu explicitamente o peer; os timestamps anteriores sao preservados.
- `failed`, `withdrawn`, `expired` e `dry_run`: respectivamente falha, retirada confirmada pela aplicacao, TTL encerrado com retirada concluida e simulacao.
- `failed_withdraw`: a retirada falhou ou ficou incerta; a regra continua reservada, pode permanecer ativa e sera reconciliada novamente.

O nivel `peer_established_announce_requested` confirma somente que o GMJ-FLOW entregou o comando ao ExaBGP com o peer estabelecido e solicitou o anuncio. Ele nao confirma, sozinho, a presenca da rota na RIB FlowSpec do Huawei. Sem consulta direta e conclusiva ao roteador, a interface deve tratar a confirmacao como local. Uma porta TCP/179 acessivel indica apenas transporte disponivel e nao prova sessao BGP estabelecida.

O prazo de seguranca e armado na intencao duravel imediatamente anterior a escrita no pipe e e preservado em `sent`/`advertised`. Se o processo cair depois da escrita e antes de salvar `sent`, o reconciliador envia um withdraw conservador ao fim do prazo; um withdraw redundante e seguro. `pending_approval`, `dry_run` e `queued` sem tentativa nao expiram operacionalmente.

O relogio vencido, sozinho, nao comprova que o withdraw foi entregue. Um registro `advertised` continua contado e exibido como potencialmente ativo ate mudar para `expired` ou `withdrawn`; durante essa janela a interface informa retirada atrasada/pendente. Isso tambem impede que uma nova regra equivalente seja anunciada e depois removida por um withdraw antigo. Registros legados `active`/`announced` permanecem visiveis como enviados sem confirmacao e nao entram na contagem operacional.

## Autostart

```sh
sudo ./scripts/install-systemd-service.sh --profile ai --with-exabgp
systemctl status gmj-flow
```

Os serviços Docker principais também usam `restart: unless-stopped`.

## Validações

```sh
sudo ./scripts/post-install-check.sh
docker compose --env-file .env -f docker-compose.yml -f docker-compose.collectors.yml --profile ai config
curl http://127.0.0.1:8000/health
docker exec gmj-flow-clickhouse clickhouse-client --query "SELECT count(), max(flow_time) FROM flowdb.flow_raw"
```

## Troubleshooting rápido

- `gmj-flow-ollama` não existe: suba com `--with-ai` ou `--profile ai`.
- `ollama list` vazio: use `Sistema > IA Local > Baixar` ou `docker exec gmj-flow-ollama ollama pull qwen2.5:3b-instruct`.
- IA desativada HTTP 409: habilite em `Sistema > IA Local`.
- Pipe ExaBGP down: rode `sudo ./scripts/install-exabgp.sh ...` e valide `/run/exabgp`.
- Backend nao ve `/run/exabgp`: use `-f docker-compose.exabgp-pipe.yml` e recrie `backend frontend`.
- Frontend 502 após recriar backend: confirme `frontend/nginx.conf` com `resolver 127.0.0.11`.
- GMJ-FLOW não sobe após reboot: instale `gmj-flow.service` e confira `systemctl is-enabled gmj-flow`.
- PDF com números crus: exporte Flows novamente; o PDF deve mostrar `Mbps`, `Kpps`, `MB`, `K/M/G`.
