import React from 'react';

/**
 * BLOCO 3 — primitive reutilizável de interface (R5/R6).
 *
 * Chave lógica: (exporter_ip, ifIndex). O ifIndex NUNCA é resolvido sozinho:
 * o mesmo ifIndex existe em equipamentos diferentes (ex.: 138 em
 * 179.189.80.0 = LINk_AMT_REAL e em 45.163.144.1 = LINK_IP_FALCONNET).
 *
 * Precedência: inventory (nome/alias/descrição) > observed (sem nome).
 * Fallback: sempre mostra `ifIndex N` cru — nunca inventa nome nem esconde o
 * valor bruto. Não faz chamada HTTP por linha: recebe os campos já resolvidos
 * pelo backend (`input_if_name`, `input_interface_source`, ...).
 */

function label(item) {
  const name = (item.name && String(item.name).trim()) || '';
  const ifIndex = item.ifIndex;
  if (name) return { main: name, raw: ifIndex };
  return { main: '', raw: ifIndex };
}

export default function InterfaceRef({
  exporterIp,
  sensorId,
  sensorName,
  ifIndex,
  name,
  alias,
  descr,
  source,
  compact = true,
  onOpen,
}) {
  const index = ifIndex === null || ifIndex === undefined || ifIndex === '' ? null : Number(ifIndex);
  if (index === null || Number.isNaN(index) || index <= 0) {
    return <span className="v2-muted">—</span>;
  }
  const resolved = label({ name, ifIndex: index });
  const secondary = [alias, descr].filter((value) => value && String(value).trim()).join(' · ');
  const origin = String(source || '').toLowerCase();
  const title = [
    sensorName ? `sensor ${sensorName}` : sensorId ? `sensor #${sensorId}` : '',
    exporterIp ? `exporter ${exporterIp}` : '',
    `ifIndex ${index}`,
    origin === 'inventory' ? 'nome do inventário' : origin === 'observed' ? 'observada em flow (sem cadastro)' : '',
  ].filter(Boolean).join(' · ');

  return (
    <span className="iref" title={title}>
      {resolved.main ? (
        <>
          <b>{resolved.main}</b>
          {compact ? <span className="v2-muted"> · ifIndex {index}</span> : null}
        </>
      ) : (
        <span className="v2-muted">ifIndex {index}</span>
      )}
      {origin === 'observed' ? <i className="iref-src" title="Interface vista no tráfego sem cadastro no inventário">observed</i> : null}
      {!compact && secondary ? <div className="v2-note" style={{ marginTop: 2 }}>{secondary}</div> : null}
      {onOpen ? (
        <button
          type="button"
          className="v2-mini"
          onClick={() => onOpen({ exporterIp, sensorId, sensorName, ifIndex: index })}
        >
          ver
        </button>
      ) : null}
    </span>
  );
}
