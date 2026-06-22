# Calibracao de sample_rate por SNMP

O GMJ-FLOW pode estimar o `sample_rate` real comparando counters SNMP de interface com o trafego bruto recebido via Flow.

## Como funciona

1. Sensores ativos com `exporter_snmp_enabled=true` sao consultados por SNMP.
2. O backend coleta `ifHCInOctets` e `ifHCOutOctets` por `ifIndex`.
3. A diferenca entre duas amostras gera `in_bps` e `out_bps`.
4. A calibracao compara uma janela recente, normalmente 5 a 15 minutos:
   - SNMP `in_bps` contra Flow `input_if`;
   - SNMP `out_bps` contra Flow `output_if`.
5. O fator estimado e calculado como:

```text
sample_rate_estimado = snmp_bps / flow_bps_bruto
```

O backend usa a mediana dos pontos validos e ignora zeros, valores baixos e outliers simples.

## Tabelas SQLite

`interface_snmp_samples` guarda as amostras SNMP:

- `sensor_id`
- `if_index`
- `sample_time`
- `in_octets`
- `out_octets`
- `in_bps`
- `out_bps`
- `if_oper_status`

`sensor_interface_calibration` guarda a ultima estimativa:

- `sensor_id`
- `if_index`
- `estimated_sample_rate_in`
- `estimated_sample_rate_out`
- `confidence`
- `last_calibrated_at`
- `method = snmp_vs_flow`

A tabela de interfaces tambem guarda `sample_rate_in` e `sample_rate_out`, usados quando o operador aplica uma calibracao confiavel.

O operador tambem pode salvar manualmente `sample_rate_in` e `sample_rate_out` pela tela de interfaces. Para Huawei com `sampler fix-packets 1000`, use `1000` em IN e OUT quando a configuracao do roteador for simetrica.

O GMJ-FLOW aplica o fator nas consultas de Dashboard, Registros de Flow e TOP Flow:

- trafego de entrada usa `sample_rate_in` da interface `input_if`;
- trafego de saida usa `sample_rate_out` da interface `output_if`;
- se a interface nao estiver cadastrada, usa `flow_raw.sample_rate`;
- `bytes` e `packets` sao corrigidos;
- `flow_count` nao e multiplicado por sample-rate.

## Endpoints

```text
POST /api/sensors/{sensor_id}/snmp/poll
POST /api/sensors/{sensor_id}/interfaces/calibration/run
POST /api/sensors/{sensor_id}/interfaces/{if_index}/calibration/run
GET  /api/sensors/{sensor_id}/interfaces/{if_index}/calibration
POST /api/sensors/{sensor_id}/interfaces/{if_index}/calibration/apply
PUT  /api/sensors/{sensor_id}/interfaces/{if_index}/sample-rate
GET  /api/sensors/{sensor_id}/interfaces/{if_index}/diagnostics
```

O endpoint de apply nao aplica automaticamente quando a confianca esta abaixo de `GMJFLOW_CALIBRATION_MIN_CONFIDENCE`, padrao `0.6`.

## Variaveis

```env
GMJFLOW_SNMP_POLLING_ENABLED=1
GMJFLOW_CALIBRATION_MIN_BPS=10000
GMJFLOW_CALIBRATION_MIN_CONFIDENCE=0.6
```

O polling em background roda dentro do backend e respeita `snmp_polling_seconds` de cada sensor, com minimo efetivo de 30 segundos.

## Limites conhecidos

- SNMP mede a interface inteira.
- Flow pode representar apenas parte do trafego real.
- Trafego local, descartado, filtrado ou processado fora do caminho de exportacao pode divergir.
- sFlow, IPFIX e NetFlow podem ter particularidades por vendor.
- A primeira amostra SNMP nao gera taxa; e necessario ter pelo menos duas amostras para calcular delta.
- O fator aplicado fica salvo na interface; ele nao altera automaticamente collectors ou parsers existentes.
