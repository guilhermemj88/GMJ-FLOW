# Vetores de Ataque e Anomalias

O modulo de anomalias do GMJ-FLOW adiciona uma camada de analise automatica sobre os flows gravados em `flowdb.flow_raw`. A ideia e separar configuracao de deteccao e eventos detectados:

- **Vetor de ataque**: uma regra configuravel pelo usuario. Define dominio, alvo, direcao, decoder, unidade, threshold, severidade e resposta.
- **Anomalia**: um evento criado pelo worker quando um vetor ativo ultrapassa o threshold em uma janela recente.

## Templates

A tela **Vetores de Ataque** organiza regras em templates. Um template pode ser ativado/desativado, duplicado e usado como base para aprendizado automatico.

O GMJ-FLOW cria o template inicial `THRESHOLD-PADRAO` quando o SQLite ainda nao possui templates. Ele contem thresholds conservadores para trafego recebido em IPs internos. Esses valores sao apenas ponto de partida; o recomendado e rodar o aprendizado automatico por pelo menos 2 dias.

## Campos do vetor

- **Dominio**: escopo da regra. Valores: `any`, `internal_ip`, `external_ip`, `prefix`, `sensor`, `interface`.
- **Alvo**: IP ou CIDR, como `192.168.0.10/32` ou `192.168.0.0/24`. Pode ficar vazio em regras globais.
- **Sensor**: limita a regra a um sensor/exportador cadastrado.
- **Interface**: limita a regra a um `ifIndex` do sensor.
- **Direcao**: `receives`, `sends` ou `both`.
- **Decoder**: classifica o tipo de trafego analisado.
- **Comparacao**: no MVP, apenas `over`.
- **Unidade**: `bits_s`, `packets_s` ou `flows_s`.
- **Severidade**: `info`, `warning` ou `critical`.
- **Resposta**: `alert_only`, `response_ip`, `webhook_future` ou `ignore`.

## Decoders

O backend possui uma funcao testavel de classificacao de flows e tambem empurra filtros equivalentes para o ClickHouse quando possivel.

Decoders suportados:

- `IP`: qualquer protocolo.
- `TCP`, `TCP+ALL`: protocolo 6.
- `TCP+SYN`, `TCP+SYNACK`, `TCP+ACK`, `TCP+RST`, `TCP+NULL`: protocolo TCP com flags correspondentes.
- `UDP`: protocolo 17.
- `ICMP`: protocolos 1 e 58.
- `DNS`: porta 53 UDP/TCP.
- `NTP`: porta 123 UDP.
- `QUIC`, `UDP+QUIC`: UDP 443 ou 8443.
- `HTTP`, `HTTPS`, `MAIL`, `SIP`, `IPSEC`, `NETBIOS`, `MEMCACHED`: portas/protocolos conhecidos.
- `FLOWS`: usa `flow_count` por segundo.
- `OTHER`: trafego que nao bate nos decoders conhecidos.
- `FRAGMENT` e `INVALID`: reservados.

## Aprendizado automatico

Endpoint:

```http
POST /api/attack-vectors/learn
```

Exemplo:

```json
{
  "template_id": 1,
  "days": 2,
  "margin_percent": 20,
  "sensor_id": null,
  "target_cidr": null
}
```

O aprendizado consulta o ClickHouse nos ultimos `N` dias e gera sugestoes por decoder, direcao e unidade. O calculo usa `p95`, `p99`, maximo e media, ignorando periodos sem trafego e valores muito baixos. A sugestao usa `p99` ou maximo com margem de seguranca; se o maximo estiver muito acima do `p99`, o `p99` e preferido para reduzir o risco de aprender um ataque antigo como normal.

As sugestoes ficam pendentes na tela ate o usuario aplicar uma a uma ou aplicar todas.

## Motor de deteccao

Variaveis de ambiente:

```env
GMJFLOW_ANOMALY_DETECTION_ENABLED=true
GMJFLOW_ANOMALY_INTERVAL_SECONDS=30
GMJFLOW_ANOMALY_LOOKBACK_SECONDS=60
GMJFLOW_ANOMALY_MIN_DURATION_SECONDS=30
GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS=120
```

A cada intervalo, o worker:

1. Carrega vetores ativos em templates ativos.
2. Consulta `flow_raw` na janela recente.
3. Agrega `bits/s`, `packets/s` e `flows/s`.
4. Compara com o threshold.
5. Cria ou atualiza uma anomalia ativa usando chave de deduplicacao.
6. Salva uma amostra de flows relacionados.
7. Encerra eventos ativos que nao aparecem novamente dentro de `GMJFLOW_ANOMALY_CLOSE_AFTER_SECONDS`.

A deduplicacao usa:

```text
attack_vector_id + target_ip + sensor_id + interface_if_index + decoder + direction
```

## Tela Anomalias

A tela **Anomalias** possui abas:

- **Ativas**: eventos abertos agora.
- **Historico**: eventos encerrados ou reconhecidos.

O menu lateral mostra um badge pulsante quando ha anomalias ativas. Em cada evento e possivel abrir detalhes, reconhecer ou encerrar manualmente.

Os detalhes exibem resumo textual, grafico simples a partir das amostras, flows relacionados e top conversas.

## Limitacoes

- O MVP usa `flow_raw` diretamente; em ambientes grandes, recomenda-se evoluir para agregacoes precomputadas por minuto e decoder.
- `FRAGMENT` esta reservado ate existir campo de fragmentacao no flow.
- A classificacao `OTHER` e conservadora e pode mudar conforme novos decoders forem adicionados.
- O aprendizado depende da qualidade historica do periodo escolhido. Se houve ataque durante a janela, revise as sugestoes antes de aplicar.

## Exemplos praticos

Regra para UDP recebido acima de 5 Gbps em IPs internos:

- Dominio: `internal_ip`
- Direcao: `receives`
- Decoder: `UDP`
- Comparacao: `over`
- Valor: `5000000000`
- Unidade: `bits_s`
- Severidade: `warning`

Regra para SYN flood recebido acima de 1 Mpps:

- Dominio: `internal_ip`
- Direcao: `receives`
- Decoder: `TCP+SYN`
- Comparacao: `over`
- Valor: `1000000`
- Unidade: `packets_s`
- Severidade: `warning`
