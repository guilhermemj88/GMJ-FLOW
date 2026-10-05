import React, { useState } from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Panel, Table, fmtNumber, fmtTime, useApi,
} from './shared.jsx';

/**
 * BLOCO 3 — Sensores V2 (master/detail, somente leitura).
 *
 * Lista: GET /api/sensors?include_interfaces=false  (modo LEVE — sem o fan-out
 * de enriquecimento que causava 504).
 * Detalhe: GET /api/sensors/{id}/interfaces?monitor=all (só do sensor escolhido).
 * Contagens de cadastradas/monitoradas: total do /api/interfaces com limit=1.
 */

function Detail({ sensor, onNavigate }) {
  const countAll = useApi(`/api/interfaces?sensor_id=${sensor.id}&monitor=all&limit=1`, { deps: [sensor.id] });
  const countMon = useApi(`/api/interfaces?sensor_id=${sensor.id}&monitor=enabled&limit=1`, { deps: [sensor.id] });
  const list = useApi(`/api/sensors/${sensor.id}/interfaces?monitor=all&limit=500`, { deps: [sensor.id] });
  const items = list.data?.items || [];
  const cadastradas = countAll.data?.total;
  const monitoradas = countMon.data?.total;
  const overrides = items.filter((i) => i.sample_rate_override).length;

  return (
    <>
      <Panel
        title={sensor.name || `Sensor #${sensor.id}`}
        subtitle={`exporter ${sensor.exporter_ip || '—'} · listener ${sensor.listener_port || '—'} · sample-rate mode ${sensor.sample_rate_mode || '—'}`}
        badge={sensor.active ? 'ativo' : 'inativo'}
        badgeTone={sensor.active ? 'ok' : 'muted'}
      >
        <div className="v2-cells">
          <div><span>Exporter</span><b className="mono">{sensor.exporter_ip || '—'}</b></div>
          <div><span>Sample-rate default in/out</span><b>{sensor.sample_rate_default_in ?? '—'}/{sensor.sample_rate_default_out ?? '—'}</b></div>
          <div><span>Cadastradas</span><b>{fmtNumber(cadastradas)}</b></div>
          <div><span>Monitoradas</span><b>{fmtNumber(monitoradas)}</b></div>
          <div><span>Overrides nas monitoradas</span><b>{fmtNumber(overrides)}</b></div>
          <div><span>Observadas em flow</span><b className="v2-muted">não disponível nesta lista</b></div>
          <div><span>Última atualização do cadastro</span><b>{sensor.updated_at ? fmtTime(sensor.updated_at) : '—'}</b></div>
          <div><span>Ingestão / saúde</span><b><a className="v2-link" href="#" onClick={(e) => { e.preventDefault(); onNavigate && onNavigate('alerts'); }}>ver em Alertas (coletores)</a></b></div>
        </div>
        <div className="v2-note" style={{ marginTop: 8 }}>
          Cadastrada ≠ monitorada ≠ observada em flow. “Sem flow recente” não significa interface offline.
        </div>
      </Panel>
      <Panel
        title="Interfaces do sensor"
        subtitle="monitor=all · inclui as cadastradas que não estão monitoradas"
        badge={list.error ? 'Indisponível' : fmtNumber(items.length)}
        badgeTone={list.error ? 'warning' : 'info'}
      >
        {list.error ? <ErrorBox message={list.error} /> : null}
        {list.loading ? <Loading /> : (
          <div className="v2-dense-wrap">
            <table className="v2-dense">
              <thead>
                <tr>
                  <th>ifIndex</th><th>Nome</th><th>Alias</th><th>MON</th>
                  <th>Rate in/out</th><th>Rate efetivo</th><th>Amostra SNMP</th><th>Status</th><th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {items.length ? items.map((row) => (
                  <tr key={row.id || `${row.if_index}`}>
                    <td className="mono">{row.if_index}</td>
                    <td><b>{row.if_name || <span className="v2-muted">sem nome</span>}</b></td>
                    <td className="v2-muted">{row.if_alias || row.if_descr || '—'}</td>
                    <td>{row.monitor_enabled ? <Badge tone="ok">sim</Badge> : <span className="v2-chip muted">não</span>}</td>
                    <td className="mono">{row.sample_rate_in}/{row.sample_rate_out}
                      {row.sample_rate_override ? <span className="v2-chip warn">override</span> : <span className="v2-chip muted">default</span>}
                    </td>
                    <td className="mono">{row.effective_sample_rate_in ?? '—'}/{row.effective_sample_rate_out ?? '—'}</td>
                    <td>{row.snmp_sample_time ? fmtTime(row.snmp_sample_time) : <span className="v2-chip muted">sem amostra</span>}</td>
                    <td>{row.snmp_if_oper_status || <span className="v2-muted">—</span>}</td>
                    <td>
                      <button type="button" className="v2-mini"
                        onClick={() => onNavigate && onNavigate('flows', { ifIndex: row.if_index, sensorName: sensor.name })}>
                        investigar em Flows
                      </button>
                    </td>
                  </tr>
                )) : (
                  <tr><td colSpan={9}><EmptyState title="Nenhuma interface cadastrada" hint="Este sensor não possui interfaces no inventário." /></td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

export default function Sensors({ onNavigate }) {
  const data = useApi('/api/sensors?include_interfaces=false');
  const rows = data.data?.items || [];
  const [selected, setSelected] = useState(null);
  const current = rows.find((r) => r.id === selected) || rows[0] || null;

  return (
    <div className="page">
      <div className="v2-readonly-note">
        <Badge tone="critical">SOMENTE LEITURA</Badge>
        <span>Lista em <b>modo leve</b> (<span className="mono">include_interfaces=false</span>): o payload pesado (238 interfaces) não é baixado; as interfaces vêm só do sensor selecionado.</span>
      </div>
      <div className="v2-split">
        <Panel title="Sensores" subtitle="inventário real" badge={data.error ? 'Indisponível' : fmtNumber(rows.length)} badgeTone={data.error ? 'warning' : 'info'}>
          {data.error ? <ErrorBox message={data.error} /> : null}
          {data.loading ? <Loading /> : (
            <ul className="v2-master">
              {rows.map((s) => (
                <li key={s.id}
                  className={current && current.id === s.id ? 'v2-master-item on' : 'v2-master-item'}
                  onClick={() => setSelected(s.id)}>
                  <b>{s.name}</b>
                  <span className="mono">{s.exporter_ip || '—'}</span>
                  <span className="v2-note">
                    rate {s.sample_rate_default_in ?? '—'}/{s.sample_rate_default_out ?? '—'} · {s.sample_rate_mode || '—'}
                    {s.active ? '' : ' · inativo'}
                  </span>
                </li>
              ))}
              {!rows.length ? <li className="v2-note">Nenhum sensor retornado.</li> : null}
            </ul>
          )}
        </Panel>
        <div>{current ? <Detail sensor={current} onNavigate={onNavigate} /> : <EmptyState title="Selecione um sensor" />}</div>
      </div>
    </div>
  );
}
