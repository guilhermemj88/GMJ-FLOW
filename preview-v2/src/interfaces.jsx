import React, { useState } from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Panel, Table, fmtNumber, useApi,
} from './shared.jsx';

/**
 * BLOCO 3 — Interfaces V2 (Dense Interface Inventory) · somente leitura.
 *
 * Fonte canônica: GET /api/interfaces (paginado, server-side).
 * Chave: (exporter_ip, ifIndex) — ifIndex igual NÃO significa mesma interface.
 * cadastrada ≠ monitorada ≠ observada em flow.
 */

export default function Interfaces({ onNavigate }) {
  const [filters, setFilters] = useState({ monitor: 'all', q: '', sensor_id: '', exporter_ip: '', sample_rate_override: '' });
  const [page, setPage] = useState(0);
  const limit = 100;
  const sensors = useApi('/api/sensors?include_interfaces=false');
  const sensorRows = sensors.data?.items || [];

  const params = new URLSearchParams();
  if (filters.monitor) params.set('monitor', filters.monitor);
  if (filters.q) params.set('q', filters.q);
  if (filters.sensor_id) params.set('sensor_id', filters.sensor_id);
  if (filters.exporter_ip) params.set('exporter_ip', filters.exporter_ip);
  if (filters.sample_rate_override) params.set('sample_rate_override', filters.sample_rate_override);
  params.set('limit', String(limit));
  params.set('offset', String(page * limit));
  const query = params.toString();
  const data = useApi(`/api/interfaces?${query}`, { deps: [query] });
  const items = data.data?.items || [];
  const total = data.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / limit));

  const setField = (key, value) => { setPage(0); setFilters((prev) => ({ ...prev, [key]: value })); };

  return (
    <div className="page">
      <div className="v2-readonly-note">
        <Badge tone="critical">SOMENTE LEITURA</Badge>
        <span>Inventário configurado (<b>source = inventory</b>). Nome/alias/descrição vêm do cadastro; o ifIndex cru é sempre exibido. “Observada em flow” não é calculada nesta lista (gap registrado).</span>
      </div>
      <Panel
        title="Interfaces"
        subtitle="Dense Interface Inventory · identidade (exporter_ip, ifIndex) · paginação server-side"
        badge={data.error ? 'Indisponível' : `${fmtNumber(total)} interfaces`}
        badgeTone={data.error ? 'warning' : 'info'}
        filters={
          <div className="v2-filters">
            <label className="v2-field"><span>Sensor</span>
              <select value={filters.sensor_id} onChange={(e) => setField('sensor_id', e.target.value)}>
                <option value="">todos</option>
                {sensorRows.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </label>
            <label className="v2-field"><span>Exporter</span>
              <input value={filters.exporter_ip} placeholder="179.189.80.0" onChange={(e) => setField('exporter_ip', e.target.value)} />
            </label>
            <label className="v2-field"><span>Monitor</span>
              <select value={filters.monitor} onChange={(e) => setField('monitor', e.target.value)}>
                <option value="all">todas (cadastradas)</option>
                <option value="enabled">somente monitoradas</option>
              </select>
            </label>
            <label className="v2-field"><span>Sample-rate</span>
              <select value={filters.sample_rate_override} onChange={(e) => setField('sample_rate_override', e.target.value)}>
                <option value="">todos</option>
                <option value="override">com override</option>
                <option value="default">usando default</option>
              </select>
            </label>
            <label className="v2-field"><span>Busca</span>
              <input value={filters.q} placeholder="nome, alias, descrição ou ifIndex" onChange={(e) => setField('q', e.target.value)} />
            </label>
            <button type="button" className="control" onClick={() => { setFilters({ monitor: 'all', q: '', sensor_id: '', exporter_ip: '', sample_rate_override: '' }); setPage(0); }}>Limpar</button>
          </div>
        }
      >
        {data.error ? <ErrorBox message={data.error} /> : null}
        {sensors.error ? <ErrorBox message={`Sensores: ${sensors.error}`} /> : null}
        {data.loading ? <Loading /> : (
          <div className="v2-dense-wrap">
            <table className="v2-dense">
              <thead>
                <tr>
                  <th>Sensor</th><th>Exporter</th><th>ifIndex</th><th>Nome</th><th>Alias</th><th>Descrição</th>
                  <th>MON</th><th>Rate in/out</th><th>Origem</th><th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {items.length ? items.map((row) => (
                  <tr key={`${row.exporter_ip}-${row.if_index}`}>
                    <td>{row.sensor_name || `#${row.sensor_id}`}{row.sensor_active ? '' : <span className="v2-chip muted">inativo</span>}</td>
                    <td className="mono">{row.exporter_ip}</td>
                    <td className="mono">{row.if_index}</td>
                    <td><b>{row.if_name || <span className="v2-muted">sem nome</span>}</b></td>
                    <td className="v2-muted">{row.if_alias || '—'}</td>
                    <td className="v2-muted">{row.if_descr || '—'}</td>
                    <td>{row.monitor_enabled ? <Badge tone="ok">sim</Badge> : <span className="v2-chip muted">não</span>}</td>
                    <td className="mono">
                      {row.sample_rate_in}/{row.sample_rate_out}
                      {row.sample_rate_override
                        ? <span className="v2-chip warn" title="valor específico desta interface">override</span>
                        : <span className="v2-chip muted" title={`default do sensor: ${row.sample_rate_default_in}/${row.sample_rate_default_out}`}>default</span>}
                    </td>
                    <td><span className="v2-chip muted">inventory</span></td>
                    <td>
                      <button type="button" className="v2-mini"
                        onClick={() => onNavigate && onNavigate('flows', { ifIndex: row.if_index, sensorName: row.sensor_name })}>
                        investigar em Flows
                      </button>
                      <button type="button" className="v2-mini"
                        onClick={() => onNavigate && onNavigate('sensors', { sensorId: row.sensor_id })}>
                        sensor
                      </button>
                    </td>
                  </tr>
                )) : (
                  <tr><td colSpan={10}><EmptyState title="Nenhuma interface" hint="Ajuste os filtros: por padrão mostramos todas as cadastradas (monitor=all)." /></td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
        <div className="v2-pager">
          <span className="v2-note">{fmtNumber(total)} interfaces · página {page + 1} de {pages}</span>
          <button type="button" className="control" disabled={page <= 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>Anterior</button>
          <button type="button" className="control" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}>Próxima</button>
        </div>
        <div className="v2-note" style={{ padding: '0 12px 12px' }}>
          <b>ifIndex igual ≠ mesma interface:</b> teste o filtro por exporter — <span className="mono">179.189.80.0</span> · ifIndex 138
          é <b>LINk_AMT_REAL</b>, enquanto <span className="mono">45.163.144.1</span> · ifIndex 138 é <b>LINK_IP_FALCONNET</b>.
          Cadastrada (inventário) ≠ monitorada (MON=sim) ≠ observada em flow.
        </div>
      </Panel>
    </div>
  );
}
