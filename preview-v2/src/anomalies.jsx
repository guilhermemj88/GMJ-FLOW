import React, { useEffect, useState } from 'react';
import {
  Badge, ErrorBox, Loading, Panel, Table, useApi,
  fmtBits, fmtNumber, fmtPps, fmtTime, severityTone, statusTone,
} from './shared.jsx';

const READ_ONLY = 'Somente leitura';

const SEVERITY_OPTIONS = [['', 'Todas'], ['critical', 'critical'], ['warning', 'warning'], ['info', 'info']];
const PERIOD_OPTIONS = [
  ['', 'Sem filtro'], ['1h', 'Última hora'], ['4h', 'Últimas 4 h'], ['12h', 'Últimas 12 h'],
  ['24h', 'Últimas 24 h'], ['today', 'Hoje'], ['yesterday', 'Ontem'], ['7d', 'Últimos 7 dias'],
];

function presetRange(preset) {
  const now = new Date();
  const iso = (d) => d.toISOString();
  const hours = (h) => new Date(now.getTime() - h * 3600e3);
  if (preset === '1h') return [iso(hours(1)), iso(now)];
  if (preset === '4h') return [iso(hours(4)), iso(now)];
  if (preset === '12h') return [iso(hours(12)), iso(now)];
  if (preset === '24h') return [iso(hours(24)), iso(now)];
  if (preset === '7d') return [iso(new Date(now.getTime() - 7 * 86400e3)), iso(now)];
  if (preset === 'today') { const d = new Date(now); d.setHours(0, 0, 0, 0); return [iso(d), iso(now)]; }
  if (preset === 'yesterday') {
    const start = new Date(now); start.setHours(0, 0, 0, 0); start.setDate(start.getDate() - 1);
    const end = new Date(start); end.setHours(23, 59, 59, 999);
    return [iso(start), iso(end)];
  }
  return ['', ''];
}

function unitFmt(unit, value) {
  const u = String(unit || '').toLowerCase();
  if (u.includes('bit')) return fmtBits(value);
  if (u.includes('packet') || u === 'pps') return fmtPps(value);
  if (u.includes('flow')) return `${fmtNumber(value, 2)} flows/s`;
  return value == null ? '—' : `${fmtNumber(value, 2)} ${unit || ''}`.trim();
}

function Field({ label, children }) {
  return <label className="v2-field"><span>{label}</span>{children}</label>;
}

/**
 * BLOCO 2 (Estratégia C): rótulos da condição REAL do detector.
 *
 * `metric` chega na unidade canônica do backend (`packets_per_second`) e
 * `comparison` na convenção real dos detectores (`over` = observado >= limiar).
 * A cardinalidade só aparece como condição quando ela PARTICIPA do HAVING
 * (vetores de upload many-clients) — nunca por padrão.
 */
function metricLabel(metric) {
  const key = String(metric || '').toLowerCase();
  if (key === 'packets_per_second' || key === 'packets_s' || key === 'pps') return 'PPS (packets/s)';
  if (key === 'bits_per_second' || key === 'bits_s' || key === 'bps') return 'Bitrate (bits/s)';
  if (key === 'flows_per_second' || key === 'flows_s') return 'Flows/s';
  if (key === 'unique_src_ips') return 'Origens distintas observadas';
  return metric ? String(metric) : '';
}

function cmpLabel(comparison) {
  const key = String(comparison || '').toLowerCase();
  if (key === 'over' || key === 'gte' || key === '>=') return '>=';
  if (key === 'gt' || key === '>') return '>';
  if (key === 'below' || key === 'lte' || key === '<=') return '<=';
  if (key === 'lt' || key === '<') return '<';
  return '>=';
}

function Chart({ points, valueKey, label }) {
  const list = (points || []).filter((p) => Number.isFinite(Number(p[valueKey])));
  if (list.length < 2) return <div className="v2-note" style={{ padding: '10px 12px' }}>Série indisponível para {label}.</div>;
  const W = 900, H = 90;
  const values = list.map((p) => Number(p[valueKey]));
  const max = Math.max(1, ...values);
  const n = list.length;
  const x = (i) => (i / (n - 1)) * W;
  const y = (v) => H - (v / max) * (H - 8) - 4;
  return (
    <div className="v2-chart">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-label={`Série de ${label}`}>
        <polyline fill="none" stroke="#22d3ee" strokeWidth="2" points={list.map((p, i) => `${x(i)},${y(Number(p[valueKey]))}`).join(' ')} />
      </svg>
      <div className="v2-note" style={{ position: 'absolute', left: 8, bottom: 4 }}>
        {label} · {list.length} pontos · pico {unitFmt(valueKey === 'bits_s' ? 'bits_s' : 'packets_s', max)}
      </div>
    </div>
  );
}

function Drawer({ title, context, onClose, children }) {
  return (
    <div className="v2-drawer-overlay" onClick={onClose}>
      <aside className="v2-drawer" onClick={(e) => e.stopPropagation()}>
        <header>
          <div><div className="v2-muted">{context}</div><h2>{title}</h2></div>
          <button type="button" className="control" onClick={onClose} aria-label="Fechar">×</button>
        </header>
        <div className="v2-drawer-body">{children}</div>
      </aside>
    </div>
  );
}

function Section({ title, children, open = true }) {
  const [expanded, setExpanded] = useState(open);
  return (
    <div className="v2-acc">
      <button type="button" className="v2-acc-head" onClick={() => setExpanded(!expanded)}>
        <span>{title}</span><span style={{ color: 'var(--cyan)' }}>{expanded ? '▾' : '▸'}</span>
      </button>
      {expanded ? <div className="v2-acc-body">{children}</div> : null}
    </div>
  );
}

function Cells({ entries }) {
  const list = entries.filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!list.length) return <div className="v2-note">Sem dados.</div>;
  return (
    <div className="v2-grid4">
      {list.map(([label, value]) => <div className="v2-cell" key={label}><span>{label}</span><b>{String(value)}</b></div>)}
    </div>
  );
}

function mitigationLabel(item) {
  const state = String(item.auto_mitigation_status || '').trim();
  const response = String(item.response_status || '').trim();
  if (response === 'advertised' || response === 'confirmed') return ['confirmada BGP', 'success'];
  if (state) return [state, statusTone(state)];
  if (response) return [response, statusTone(response)];
  return ['não solicitada', 'info'];
}

/* --------------------------------- Root --------------------------------- */

export default function Anomalias({ focus, onNavigate }) {
  const [tab, setTab] = useState('active');
  /**
   * Cross-link do BLOCO 1 (Mitigação / BGP → Anomalias): abre o drawer da
   * anomalia pedida usando o mesmo componente da lista. Anomalias consolidadas
   * (id negativo) apenas levam para a aba correspondente — o drawer consolidado
   * depende do registro da lista, que não é buscável por id.
   */
  const [linkedRow, setLinkedRow] = useState(null);
  useEffect(() => {
    if (focus?.kind !== 'anomaly' || focus.id == null) return;
    if (Number(focus.id) < 0) { setTab('consolidated'); return; }
    setTab('active');
    setLinkedRow((current) => (current && Number(current.id) === Number(focus.id) ? current : { id: focus.id }));
  }, [focus]);
  const closeLinked = () => {
    setLinkedRow(null);
    if (linkedRow && onNavigate) onNavigate('anomalies', null);
  };
  const summary = useApi('/api/anomalies/summary');
  const s = summary.data || {};
  const isActiveTab = tab === 'active';

  return (
    <div className="main-content">
      <div className="v2-toolbar">
        <div className="v2-tabs">
          {[['active', 'Ativas'], ['history', 'Histórico'], ['consolidated', 'Consolidadas'], ['summary', 'Resumo / Rankings']].map(([id, label]) => (
            <button key={id} type="button" className={tab === id ? 'v2-tab active' : 'v2-tab'} onClick={() => setTab(id)}>{label}</button>
          ))}
        </div>
        <Badge tone="critical" pulse>{READ_ONLY}</Badge>
      </div>
      <div className="v2-kpis">
        <div className="v2-kpi"><span>Ativas</span><b>{fmtNumber(s.active_count)}</b></div>
        <div className="v2-kpi c"><span>Críticas</span><b>{fmtNumber(s.critical_count)}</b></div>
        <div className="v2-kpi w"><span>Warnings</span><b>{fmtNumber(s.warning_count)}</b></div>
        <div className="v2-kpi"><span>Consolidadas (segurança)</span><b>{fmtNumber(s.security_consolidated_count)}</b></div>
      </div>
      {summary.error ? <div className="data-panel"><ErrorBox message={summary.error} /></div> : null}

      {isActiveTab ? <ActiveTab /> : null}
      {tab === 'history' ? <HistoryTab /> : null}
      {tab === 'consolidated' ? <ConsolidatedTab /> : null}
      {tab === 'summary' ? <SummaryTab /> : null}
      {linkedRow ? <AnomalyDrawer row={linkedRow} onClose={closeLinked} /> : null}
    </div>
  );
}

/* -------------------------------- Ativas -------------------------------- */

function originTarget(item) {
  const flow = item.top_flow || {};
  const origin = item.dominant_src_ip || flow.src_ip || item.top_src_ip || '';
  const port = flow.src_port ?? item.top_src_port;
  const target = item.target_ip || item.target_cidr || flow.dst_ip || '';
  return `${origin || 'distribuída'}${port ? `:${port}` : ''} → ${target || '—'}`;
}

function ActiveTab() {
  const active = useApi('/api/anomalies/active?limit=200');
  const [openRow, setOpenRow] = useState(null);
  const [filters, setFilters] = useState({ search: '', severity: '', detector: '', protocol: '', sensor: '', interface: '', mitigated: '' });
  const list = active.data?.items || [];
  const detectors = [...new Set(list.map((i) => i.decoder).filter(Boolean))].sort();
  const protocols = [...new Set(list.map((i) => i.protocol || i.decoder).filter(Boolean))].sort();
  const sensors = [...new Set(list.map((i) => i.sensor_name).filter(Boolean))].sort();
  const interfaces = [...new Set(list.map((i) => i.interface_if_index).filter((v) => v != null))].sort();

  const filtered = list.filter((item) => {
    const text = `${item.id} ${item.vector_name} ${item.decoder} ${item.target_ip} ${item.target_cidr} ${item.sensor_name}`.toLowerCase();
    if (filters.search && !text.includes(filters.search.toLowerCase())) return false;
    if (filters.severity && String(item.severity) !== filters.severity) return false;
    if (filters.detector && String(item.decoder) !== filters.detector) return false;
    if (filters.protocol && String(item.protocol || item.decoder) !== filters.protocol) return false;
    if (filters.sensor && String(item.sensor_name) !== filters.sensor) return false;
    if (filters.interface !== '' && String(item.interface_if_index) !== String(filters.interface)) return false;
    const [label] = mitigationLabel(item);
    if (filters.mitigated === 'yes' && label === 'não solicitada') return false;
    if (filters.mitigated === 'no' && label !== 'não solicitada') return false;
    return true;
  });

  return (
    <Panel
      title="Fila de anomalias ativas"
      subtitle="Clique em uma linha para abrir a investigação"
      badge={active.error ? 'Indisponível' : `${filtered.length}/${active.data?.total ?? list.length}`}
      badgeTone={active.error ? 'warning' : 'info'}
      filters={
        <div className="v2-filters">
          <Field label="Buscar"><input value={filters.search} onChange={(e) => setFilters({ ...filters, search: e.target.value })} placeholder="id, vetor, alvo, sensor" /></Field>
          <Field label="Severidade"><select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>{SEVERITY_OPTIONS.map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select></Field>
          <Field label="Detector"><select value={filters.detector} onChange={(e) => setFilters({ ...filters, detector: e.target.value })}><option value="">Todos</option>{detectors.map((d) => <option key={d} value={d}>{d}</option>)}</select></Field>
          <Field label="Protocolo"><select value={filters.protocol} onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}><option value="">Todos</option>{protocols.map((p) => <option key={p} value={p}>{p}</option>)}</select></Field>
          <Field label="Sensor"><select value={filters.sensor} onChange={(e) => setFilters({ ...filters, sensor: e.target.value })}><option value="">Todos</option>{sensors.map((p) => <option key={p} value={p}>{p}</option>)}</select></Field>
          <Field label="Interface"><select value={filters.interface} onChange={(e) => setFilters({ ...filters, interface: e.target.value })}><option value="">Todas</option>{interfaces.map((p) => <option key={p} value={p}>{p}</option>)}</select></Field>
          <Field label="Mitigação"><select value={filters.mitigated} onChange={(e) => setFilters({ ...filters, mitigated: e.target.value })}><option value="">Todas</option><option value="yes">Solicitada/confirmada</option><option value="no">Não solicitada</option></select></Field>
        </div>
      }
    >
      {active.loading ? <Loading /> : active.error ? <ErrorBox message={active.error} /> : (
        <Table
          onRowClick={(row) => setOpenRow(row)}
          columns={[
            { key: 'severity', label: 'Sev.', render: (r) => <Badge tone={severityTone(r.severity)}>{r.severity}</Badge> },
            { key: 'id', label: 'ID' },
            { key: 'vector', label: 'Vetor / detector', render: (r) => <><b>{r.vector_name || r.display_name || '—'}</b><br /><span className="v2-muted">{r.decoder || '—'} · {r.direction || '—'}</span></> },
            { key: 'target', label: 'Origem → alvo /32', render: (r) => <span className="mono">{originTarget(r)}</span> },
            { key: 'peak', label: 'Pico', render: (r) => unitFmt(r.metric_unit, r.peak_value) },
            { key: 'flows', label: 'Flows', render: (r) => fmtNumber(r.flow_count) },
            { key: 'sensor', label: 'Sensor / if', render: (r) => `${r.sensor_name || '—'} · ${r.interface_if_index ?? '—'}` },
            { key: 'mitigation', label: 'Mitigação', render: (r) => { const [label, tone] = mitigationLabel(r); return <Badge tone={tone}>{label}</Badge>; } },
            { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
            { key: 'last_seen_at', label: 'Última', render: (r) => fmtTime(r.last_seen_at) },
          ]}
          rows={filtered}
          keyFor={(r) => r.id}
          empty="Nenhuma anomalia ativa para os filtros atuais."
        />
      )}
      {openRow ? <AnomalyDrawer row={openRow} onClose={() => setOpenRow(null)} /> : null}
    </Panel>
  );
}

/* ------------------------------- Histórico ------------------------------- */

const DEFAULT_HISTORY = { preset: '24h', status: '', severity: '', type: '', target: '', sortBy: 'event_time', sortDir: 'desc', pageSize: 25 };

function historyQuery(form, page) {
  const [startAt, endAt] = presetRange(form.preset);
  const params = {
    start_at: startAt, end_at: endAt, status: form.status, severity: form.severity,
    type: form.type, target: form.target, sort_by: form.sortBy, sort_dir: form.sortDir,
    page, page_size: form.pageSize,
  };
  const search = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== '' && v != null) search.set(k, v); });
  return search.toString();
}

function HistoryTab() {
  const [form, setForm] = useState(DEFAULT_HISTORY);
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState(() => historyQuery(DEFAULT_HISTORY, 1));
  const [openRow, setOpenRow] = useState(null);

  const data = useApi(`/api/anomalies/history?${query}`);
  const items = data.data?.items || [];
  const options = data.data?.filter_options || {};
  const statusOptions = options.statuses || ['acknowledged', 'ended', 'closed', 'resolved', 'archived'];
  const total = data.data?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / form.pageSize));
  const setField = (key, value) => setForm((prev) => ({ ...prev, [key]: value }));
  const apply = () => { setPage(1); setQuery(historyQuery(form, 1)); };
  const goTo = (next) => { setPage(next); setQuery(historyQuery(form, next)); };

  return (
    <Panel
      title="Histórico de anomalias"
      subtitle="Encerradas/arquivadas · filtros e ordenação do backend"
      badge={data.error ? 'Indisponível' : fmtNumber(total)}
      badgeTone={data.error ? 'warning' : 'info'}
      filters={
        <div className="v2-filters">
          <Field label="Período"><select value={form.preset} onChange={(e) => setField('preset', e.target.value)}>{PERIOD_OPTIONS.map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select></Field>
          <Field label="Status"><select value={form.status} onChange={(e) => setField('status', e.target.value)}><option value="">Todos</option>{statusOptions.map((v) => <option key={v} value={v}>{v}</option>)}</select></Field>
          <Field label="Severidade"><select value={form.severity} onChange={(e) => setField('severity', e.target.value)}>{SEVERITY_OPTIONS.map(([v, t]) => <option key={v} value={v}>{t}</option>)}</select></Field>
          <Field label="Tipo / vetor"><input value={form.type} onChange={(e) => setField('type', e.target.value)} placeholder="DNS, SYN…" /></Field>
          <Field label="Alvo / IP"><input value={form.target} onChange={(e) => setField('target', e.target.value)} placeholder="186.232.172.231" /></Field>
          <Field label="Ordenar"><select value={form.sortBy} onChange={(e) => setField('sortBy', e.target.value)}>{(options.sort_fields || ['event_time']).map((v) => <option key={v} value={v}>{v}</option>)}</select></Field>
          <Field label="Direção"><select value={form.sortDir} onChange={(e) => setField('sortDir', e.target.value)}><option value="desc">desc</option><option value="asc">asc</option></select></Field>
          <Field label="Tamanho"><select value={form.pageSize} onChange={(e) => setField('pageSize', Number(e.target.value))}>{[25, 50, 100].map((v) => <option key={v} value={v}>{v}</option>)}</select></Field>
          <button type="button" className="primary" onClick={apply}>Buscar</button>
          <button type="button" className="control" onClick={() => { setForm(DEFAULT_HISTORY); setPage(1); setQuery(historyQuery(DEFAULT_HISTORY, 1)); }}>Limpar</button>
        </div>
      }
    >
      {data.loading ? <Loading /> : data.error ? <ErrorBox message={data.error} /> : (
        <>
          <Table
            onRowClick={(row) => setOpenRow(row)}
            columns={[
              { key: 'severity', label: 'Sev.', render: (r) => <Badge tone={severityTone(r.severity)}>{r.severity}</Badge> },
              { key: 'id', label: 'ID' },
              { key: 'vector', label: 'Vetor / detector', render: (r) => <><b>{r.vector_name || r.attack_vector_name || '—'}</b><br /><span className="v2-muted">{r.decoder || r.protocol || '—'} · {r.direction || '—'}</span></> },
              { key: 'target', label: 'Alvo /32', render: (r) => <span className="mono">{r.target_ip || r.target_cidr || '—'}</span> },
              { key: 'peak', label: 'Pico', render: (r) => unitFmt(r.metric_unit, r.peak_value) },
              { key: 'flows', label: 'Flows', render: (r) => fmtNumber(r.flow_count) },
              { key: 'sensor', label: 'Sensor', render: (r) => r.sensor_name || '—' },
              { key: 'mitigation', label: 'Mitigação', render: (r) => { const [label, tone] = mitigationLabel(r); return <Badge tone={tone}>{label}</Badge>; } },
              { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
              { key: 'event_time', label: 'Evento', render: (r) => fmtTime(r.event_time || r.started_at) },
              { key: 'ended_at', label: 'Encerrada', render: (r) => (r.ended_at ? fmtTime(r.ended_at) : '—') },
            ]}
            rows={items}
            keyFor={(r) => r.id}
            empty="Nenhuma anomalia no histórico para os filtros atuais."
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px', color: 'var(--muted)', fontSize: 10, borderTop: '1px solid var(--border)' }}>
            <span>{fmtNumber(total)} itens · página {page} de {pageCount}</span>
            <span>
              <button type="button" className="control" disabled={page <= 1} onClick={() => goTo(Math.max(1, page - 1))}>Anterior</button>{' '}
              <button type="button" className="control" disabled={page >= pageCount} onClick={() => goTo(page + 1)}>Próxima</button>
            </span>
          </div>
        </>
      )}
      {openRow ? <AnomalyDrawer row={openRow} onClose={() => setOpenRow(null)} /> : null}
    </Panel>
  );
}

/* ----------------------------- Consolidadas ------------------------------ */

function ConsolidatedTab() {
  const active = useApi('/api/security/anomalies/active?limit=200');
  const history = useApi('/api/security/anomalies/history?page=1&page_size=50');
  const [view, setView] = useState('active');
  const [openRow, setOpenRow] = useState(null);
  const source = view === 'active' ? active : history;
  const items = source.data?.items || [];

  return (
    <Panel
      title="Anomalias consolidadas de segurança"
      subtitle="Detecção por template/regra em zonas de cliente (read-only)"
      badge={source.error ? 'Indisponível' : items.length}
      badgeTone={source.error ? 'warning' : 'info'}
      filters={
        <div className="v2-tabs" style={{ borderBottom: 0 }}>
          <button type="button" className={view === 'active' ? 'v2-tab active' : 'v2-tab'} onClick={() => setView('active')}>Ativas</button>
          <button type="button" className={view === 'history' ? 'v2-tab active' : 'v2-tab'} onClick={() => setView('history')}>Histórico</button>
        </div>
      }
    >
      {source.loading ? <Loading /> : source.error ? <ErrorBox message={source.error} /> : (
        <Table
          onRowClick={(row) => setOpenRow(row)}
          columns={[
            { key: 'severity', label: 'Sev.', render: (r) => <Badge tone={severityTone(r.severity)}>{r.severity}</Badge> },
            { key: 'vector', label: 'Vetor / template', render: (r) => <><b>{r.vector || '—'}</b><br /><span className="v2-muted">{r.template_name || '—'}</span></> },
            { key: 'zone', label: 'Zona', render: (r) => r.zone_name || '—' },
            { key: 'src', label: 'Origem → destino', render: (r) => <span className="mono">{r.src_ip || '—'} → {r.dst_ip || r.target_ip || '—'}</span> },
            { key: 'prefix', label: 'Prefixo', render: (r) => <span className="mono">{r.prefix_cidr || r.target_cidr || '—'}</span> },
            { key: 'rate', label: 'PPS / Bits', render: (r) => `${fmtPps(r.packets_s)} · ${fmtBits(r.bits_s)}` },
            { key: 'flows', label: 'Flows/s', render: (r) => fmtNumber(r.flows_s, 2) },
            { key: 'response', label: 'Resposta', render: (r) => r.response || r.recommended_action || '—' },
            { key: 'mitigation', label: 'Mitigação', render: (r) => { const [label, tone] = mitigationLabel(r); return <Badge tone={tone}>{label}</Badge>; } },
            { key: 'last_seen', label: 'Última', render: (r) => fmtTime(r.last_seen) },
          ]}
          rows={items}
          keyFor={(r) => r.id}
          empty="Nenhuma anomalia consolidada."
        />
      )}
      {openRow ? <ConsolidatedDrawer row={openRow} onClose={() => setOpenRow(null)} /> : null}
    </Panel>
  );
}

/* ---------------------------- Resumo / Rankings -------------------------- */

const RANKINGS = [
  ['vectors', 'Top vetores', '/api/anomalies/top-vectors?range_minutes=1440'],
  ['protocols', 'Top protocolos', '/api/anomalies/top-protocols?range_minutes=1440'],
  ['interfaces', 'Top interfaces', '/api/anomalies/top-interfaces?range_minutes=1440'],
  ['targets', 'Top alvos', '/api/anomalies/top-targets?range_minutes=1440'],
  ['sensors', 'Top sensores', '/api/anomalies/top-sensors?range_minutes=1440'],
];

function RankingCard({ title, endpoint }) {
  const data = useApi(endpoint);
  const items = data.data?.items || [];
  return (
    <div className="ranking-card">
      <div className="ranking-head"><div><b>{title}</b><span>24 h</span></div>{data.error ? <Badge tone="warning">Indisponível</Badge> : <Badge tone="info">{items.length}</Badge>}</div>
      {data.loading ? <Loading /> : data.error ? <ErrorBox message={data.error} /> : (
        <div className="ranking-rows">
          {items.length === 0 ? <div className="subtle" style={{ padding: '8px 10px' }}>Sem dados.</div> : items.slice(0, 5).map((item, i) => (
            <div className="ranking-row" key={`${item.key}-${i}`}>
              <span className="rk">{i + 1}</span>
              <span className="rk-key" title={String(item.key)}>{String(item.key)}</span>
              <span className="rk-val">{fmtNumber(item.count)}</span>
              <span className="rk-pct">{fmtNumber(item.packets)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SummaryTab() {
  const stats = useApi('/api/anomalies/stats?range_minutes=1440');
  const data = stats.data || {};
  const groups = [['by_severity', 'Por severidade'], ['by_status', 'Por status'], ['by_direction', 'Por direção']];
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      <Panel title="Resumo (24 h)" subtitle="Total e distribuições do backend" badge={stats.error ? 'Indisponível' : fmtNumber(data.total)} badgeTone={stats.error ? 'warning' : 'info'}>
        {stats.loading ? <Loading /> : stats.error ? <ErrorBox message={stats.error} /> : (
          <div className="v2-kpis">
            <div className="v2-kpi"><span>Total (24 h)</span><b>{fmtNumber(data.total)}</b></div>
            {(data.by_severity || []).slice(0, 3).map((row) => (
              <div className={`v2-kpi ${row.key === 'critical' ? 'c' : row.key === 'warning' ? 'w' : ''}`} key={row.key}><span>{row.key}</span><b>{fmtNumber(row.count)}</b></div>
            ))}
          </div>
        )}
      </Panel>
      <div className="v2-grid2">
        {groups.map(([key, title]) => (
          <Panel key={key} title={title} subtitle="Contagem por chave" badge={(data[key] || []).length} badgeTone="info">
            {stats.loading ? <Loading /> : stats.error ? <ErrorBox message={stats.error} /> : (
              <div className="v2-chips" style={{ paddingTop: 10 }}>
                {(data[key] || []).length === 0 ? <span className="v2-muted">Sem dados.</span> : (data[key] || []).map((row) => (
                  <span className="v2-chip" key={String(row.key)}>{String(row.key)}: {fmtNumber(row.count)}</span>
                ))}
              </div>
            )}
          </Panel>
        ))}
      </div>
      <div className="rankings-grid">
        {RANKINGS.map(([key, title, endpoint]) => <RankingCard key={key} title={title} endpoint={endpoint} />)}
      </div>
    </div>
  );
}

/* -------------------------------- Drawers -------------------------------- */

function AnomalyDrawer({ row, onClose }) {
  const id = row.id;
  const detail = useApi(`/api/anomalies/${id}`);
  const context = useApi(`/api/anomalies/${id}/flow-context`);
  const ai = useApi(`/api/anomalies/${id}/ai-analysis`);
  // A linha da lista já traz o essencial: mostramos imediatamente e enriquecemos com o detalhe.
  const anomaly = { ...row, ...(detail.data?.anomaly || {}) };
  const timeseries = detail.data?.timeseries || detail.data?.metric_points || [];
  const conversations = detail.data?.top_conversations || [];
  const flows = detail.data?.flows || detail.data?.related_flows || [];
  const [label, tone] = mitigationLabel(anomaly);

  return (
    <Drawer
      title={anomaly.vector_name ? `#${id} · ${anomaly.vector_name}` : `Anomalia #${id}`}
      context={`Investigação · anomalia${detail.loading ? ' · carregando detalhe…' : ''}`}
      onClose={onClose}
    >
      <div className="v2-readonly-note"><Badge tone="critical">{READ_ONLY}</Badge><span>Ações mutáveis (ack, close, mitigar) não são executadas pela preview.</span></div>
      <>
        {detail.error ? <ErrorBox message={detail.error} /> : null}
          <Section title="1 · Resumo e semântica">
            <Cells entries={[
              ['Severidade', anomaly.severity],
              ['Status', anomaly.status],
              ['Detector', anomaly.decoder || anomaly.protocol],
              ['Vetor', anomaly.vector_name || anomaly.attack_vector_name],
              ['Origem (maliciosa)', anomaly.dominant_src_ip || anomaly.top_src_ip],
              ['Alvo / vítima', anomaly.target_ip || anomaly.target_cidr],
              ['Escopo', anomaly.scope_type],
              ['Zona', anomaly.zone_name],
              ['Sensor', anomaly.sensor_name],
              ['Interface', anomaly.interface_if_index],
              ['Direção', anomaly.direction],
              ['Início', anomaly.started_at ? fmtTime(anomaly.started_at) : '—'],
              ['Fim', anomaly.ended_at ? fmtTime(anomaly.ended_at) : 'em andamento'],
              ['Frescor (última)', anomaly.last_seen_at ? fmtTime(anomaly.last_seen_at) : '—'],
            ]} />
            <div className="v2-note" style={{ marginTop: 8 }}>
              origem ≠ alvo/vítima · detector ≠ vetor · evento ativo ≠ tráfego ainda acontecendo
            </div>
          </Section>

          <Section title="2 · Métrica, thresholds e série temporal">
            <Cells entries={[
              ['Pico', unitFmt(anomaly.metric_unit, anomaly.peak_value)],
              ['Observado', unitFmt(anomaly.metric_unit, anomaly.observed_value)],
              ['Último valor', unitFmt(anomaly.metric_unit, anomaly.last_value)],
              ['Limiar', unitFmt(anomaly.metric_unit, anomaly.threshold_value)],
              ['Unidade', anomaly.metric_unit],
              ['Pontos da série', anomaly.timeseries_points],
              ['Duração evidência', anomaly.evidence_duration_seconds != null ? `${fmtNumber(anomaly.evidence_duration_seconds, 1)} s` : '—'],
              ['Fonte da série', detail.data?.timeseries_source],
            ]} />
            <div style={{ marginTop: 8 }}>{detail.loading ? <Loading /> : <Chart points={timeseries} valueKey="bits_s" label="bits/s" />}</div>
            {detail.data?.timeseries_warning ? <div className="v2-note" style={{ marginTop: 6 }}>{detail.data.timeseries_warning}</div> : null}
          </Section>

          <Section title="3 · Conversas, flows e evidências">
            {detail.loading ? <Loading /> : (
              <>
            <Table
              columns={[
                { key: 'conversation', label: 'Conversa' },
                { key: 'bytes', label: 'Bytes', render: (r) => fmtNumber(r.bytes) },
                { key: 'packets', label: 'Pacotes', render: (r) => fmtNumber(r.packets) },
                { key: 'flow_count', label: 'Flows', render: (r) => fmtNumber(r.flow_count) },
              ]}
              rows={conversations.slice(0, 10)}
              keyFor={(r, i) => `${r.conversation}-${i}`}
              empty="Sem conversas persistidas."
            />
            <div style={{ marginTop: 8 }}>
              <Table
                columns={[
                  { key: 'flow_time', label: 'Horário', render: (r) => fmtTime(r.flow_time) },
                  { key: 'src_ip', label: 'Origem', render: (r) => `${r.src_ip}:${r.src_port ?? ''}` },
                  { key: 'dst_ip', label: 'Destino', render: (r) => `${r.dst_ip}:${r.dst_port ?? ''}` },
                  { key: 'proto_name', label: 'Proto' },
                  { key: 'bytes', label: 'Bytes', render: (r) => fmtNumber(r.bytes) },
                  { key: 'packets', label: 'Pacotes', render: (r) => fmtNumber(r.packets) },
                ]}
                rows={flows.slice(0, 12)}
                keyFor={(r, i) => r.id || i}
                empty="Sem flows relacionados."
              />
            </div>
            <div className="v2-note" style={{ marginTop: 8 }}>
              Evidência: {detail.data?.evidence_status || '—'} · shape: {context.data?.attack_shape || '—'} ·
              {' '}unique_src {fmtNumber(context.data?.unique_src_ips ?? anomaly.unique_src_ips)} ·
              {' '}unique_dst {fmtNumber(context.data?.unique_dst_ips ?? anomaly.unique_dst_ips)}
            </div>
            {(context.data?.warnings || []).length ? <div className="v2-note" style={{ marginTop: 4 }}>Avisos: {(context.data.warnings || []).join(' · ')}</div> : null}
              </>
            )}
          </Section>

          {/* BLOCO 2 / Estratégia C: trigger real x forma do tráfego, nunca misturados. */}
          <Section title="4 · Por que disparou? (condição real do detector)">
            {(() => {
              const conditions = []
              const trigger = anomaly.trigger_condition
              if (trigger && typeof trigger === 'object' && Object.keys(trigger).length) {
                conditions.push({
                  label: metricLabel(trigger.metric) || anomaly.metric_unit || 'métrica',
                  comparison: trigger.comparison || 'over',
                  threshold: trigger.threshold,
                  observed: trigger.observed_value ?? anomaly.observed_value,
                  passed: trigger.passed !== false,
                  unit: anomaly.metric_unit,
                })
              }
              for (const extra of (Array.isArray(anomaly.conditions_passed) ? anomaly.conditions_passed : [])) {
                if (!extra || extra.condition !== 'unique_src_ips') continue
                conditions.push({
                  label: 'unique_src_ips',
                  comparison: extra.comparison || '>=',
                  threshold: extra.threshold,
                  observed: extra.observed_value ?? extra.actual,
                  passed: extra.passed !== false,
                  unit: '',
                })
              }
              if (!conditions.length) {
                return (
                  <div className="v2-note">
                    Threshold não registrado para esta anomalia (evento anterior ao enriquecimento de
                    evidência). Nada é inferido a partir dos valores atuais.
                  </div>
                )
              }
              return (
                <>
                  <Table
                    columns={[
                      { key: 'label', label: 'Condição' },
                      { key: 'txt', label: 'Threshold / observado', render: (r) => `${cmpLabel(r.comparison)} ${fmtNumber(r.threshold, 0)}${r.unit ? ` ${r.unit}` : ''} · observado ${fmtNumber(r.observed, 0)}` },
                      { key: 'passed', label: 'Relação com o disparo', render: (r) => <Badge tone={r.passed ? 'ok' : 'warning'}>{r.passed ? 'satisfeita' : 'não satisfeita'}</Badge> },
                    ]}
                    rows={conditions}
                    keyFor={(r) => r.label}
                    empty="Sem condições registradas."
                  />
                  <div className="v2-note" style={{ marginTop: 8 }}>
                    Somente condições que realmente participaram do disparo aparecem aqui — a
                    cardinalidade só entra quando é parte do detector (vetores de upload many-clients).
                  </div>
                </>
              )
            })()}
          </Section>

          <Section title="5 · Forma do tráfego (evidência de distribuição)">
            {(() => {
              const evidence = anomaly.source_details?.distribution_evidence
              if (!evidence) {
                return (
                  <div className="v2-note">
                    Forma do tráfego não registrada para esta anomalia (evento anterior ao
                    enriquecimento). A contagem bruta da linha aparece em “Conversas, flows e
                    evidências”.
                  </div>
                )
              }
              const sampling = evidence.sampling || {}
              return (
                <>
                  <Cells entries={[
                    ['Origens distintas observadas', fmtNumber(evidence.unique_src_ips_observed)],
                    ['Destinos distintos', fmtNumber(evidence.unique_dst_ips_observed)],
                    ['Portas destino distintas', fmtNumber(evidence.unique_dst_ports_observed)],
                    ['Forma (attack_shape)', evidence.attack_shape || '—'],
                    ['Critério semântico', `>= ${fmtNumber(evidence.semantic_threshold)} origens observadas = multi-source`],
                    ['Papel do critério', evidence.threshold_role === 'classification_only' ? 'classificação (não é gate)' : (evidence.threshold_role || '—')],
                    ['Usado no trigger?', evidence.used_for_trigger ? 'sim (faz parte do HAVING do detector)' : 'não'],
                    ['Amostragem', sampling.available && sampling.sample_rate ? `1:${fmtNumber(sampling.sample_rate)}` : (sampling.note || '—')],
                  ]} />
                  <div className="v2-note" style={{ marginTop: 8 }}>
                    {evidence.note || 'A cardinalidade classifica a distribuição do tráfego e não foi usada como condição para disparar este detector.'}
                  </div>
                  <div className="v2-note" style={{ marginTop: 4 }}>
                    Origens distintas <b>observadas na amostra</b> — não é o total real de origens.
                    {sampling.sensor ? ` Sensor ${sampling.sensor}${sampling.if_index ? ` · ifIndex ${sampling.if_index}` : ''}.` : ''}
                  </div>
                </>
              )
            })()}
          </Section>

          <Section title="6 · Threat Intel relacionada, eventos e IA">
            <Cells entries={[
              ['Análise IA disponível', ai.loading ? 'carregando…' : (ai.data?.available ? 'sim' : 'não')],
              ['Mensagem', ai.loading ? '—' : (ai.data?.error_message || ai.error || '—')],
              ['Classificação', anomaly.classification],
              ['Confiança', anomaly.confidence_label],
            ]} />
          </Section>

          <Section title="7 · Mitigação e BGP / FlowSpec">
            <Cells entries={[
              ['Estado da mitigação', anomaly.mitigation_state || label],
              ['Auto-mitigação', anomaly.auto_mitigation_status],
              ['Motivo', anomaly.auto_mitigation_reason],
              ['Resposta (BGP)', anomaly.response_status],
              ['Motivo da resposta', anomaly.response_reason],
              ['Anúncios vinculados', fmtNumber(anomaly.response_announcement_count)],
            ]} />
            {(anomaly.response_announcements || []).length ? (
              <div style={{ marginTop: 8 }}>
                <Table
                  columns={[
                    { key: 'id', label: 'Anúncio' },
                    { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
                    { key: 'action', label: 'Ação' },
                    { key: 'target_prefix', label: 'Alvo' },
                    { key: 'connector_name', label: 'Conector' },
                    { key: 'updated_at', label: 'Atualizado', render: (r) => fmtTime(r.updated_at) },
                  ]}
                  rows={anomaly.response_announcements}
                  keyFor={(r, i) => r.id || i}
                />
              </div>
            ) : null}
            <div className="v2-note" style={{ marginTop: 8 }}>
              mitigação solicitada ≠ confirmada no BGP · confirmação BGP ≠ confirmação de dataplane
            </div>
            <div className="v2-actions-disabled">
              <Badge tone="info">PDF</Badge>
              <span className="v2-muted">Exportação PDF existe na produção, mas exige cabeçalho de autorização — a preview não emite ações.</span>
            </div>
          </Section>

          <Section title="8 · Timeline">
            <ul className="v2-timeline">
              <li>Detecção iniciada · {fmtTime(anomaly.started_at)}</li>
              <li>Última observação · {fmtTime(anomaly.last_seen_at)}</li>
              {anomaly.acknowledged_at ? <li>Reconhecida · {fmtTime(anomaly.acknowledged_at)}</li> : null}
              {anomaly.ended_at ? <li>Encerrada · {fmtTime(anomaly.ended_at)}</li> : <li>Sem encerramento registrado (evento ativo)</li>}
              {anomaly.response_updated_at ? <li>Resposta atualizada · {fmtTime(anomaly.response_updated_at)}</li> : null}
            </ul>
          </Section>
      </>
    </Drawer>
  );
}

function ConsolidatedDrawer({ row, onClose }) {
  const [label] = mitigationLabel(row);
  return (
    <Drawer title={`${row.vector || 'Anomalia consolidada'} · ${row.id}`} context="Anomalia consolidada de segurança" onClose={onClose}>
      <div className="v2-readonly-note"><Badge tone="critical">{READ_ONLY}</Badge><span>Detalhe montado a partir do registro da lista (não há endpoint de detalhe para este tipo).</span></div>
      <Section title="1 · Identificação">
        <Cells entries={[
          ['Vetor', row.vector],
          ['Template', row.template_name],
          ['Severidade', row.severity],
          ['Status', row.status],
          ['Zona', row.zone_name],
          ['Domínio', row.domain],
          ['Direção', row.direction],
        ]} />
      </Section>
      <Section title="2 · Origem, alvo e escopo">
        <Cells entries={[
          ['Origem', row.src_ip],
          ['Destino', row.dst_ip],
          ['Alvo / vítima', row.target_ip || row.target_cidr],
          ['Prefixo', row.prefix_cidr],
          ['Escopo', row.scope_type],
          ['Papel do alvo', row.target_role],
        ]} />
        <div className="v2-note" style={{ marginTop: 8 }}>origem ≠ alvo/vítima</div>
      </Section>
      <Section title="3 · Métrica e evidência">
        <Cells entries={[
          ['PPS', fmtPps(row.packets_s)],
          ['Bits/s', fmtBits(row.bits_s)],
          ['Flows/s', fmtNumber(row.flows_s, 2)],
          ['Pacotes', fmtNumber(row.packets)],
          ['Bytes', fmtNumber(row.bytes)],
          ['Portas dst únicas', fmtNumber(row.unique_dst_ports)],
          ['IPs dst únicos', fmtNumber(row.unique_dst_ips)],
          ['IPs src únicos', fmtNumber(row.unique_src_ports)],
        ]} />
      </Section>
      <Section title="4 · Resposta e mitigação">
        <Cells entries={[
          ['Recomendação', row.recommended_action],
          ['Resposta', row.response],
          ['Mitigação', label],
          ['Motivo', row.auto_mitigation_reason],
        ]} />
        <div className="v2-note" style={{ marginTop: 8 }}>mitigação solicitada ≠ confirmada no BGP</div>
      </Section>
      <Section title="5 · Timeline">
        <ul className="v2-timeline">
          <li>Primeira ocorrência · {fmtTime(row.first_seen)}</li>
          <li>Última ocorrência · {fmtTime(row.last_seen)}</li>
          {row.acknowledged_at ? <li>Reconhecida · {fmtTime(row.acknowledged_at)}</li> : null}
          {row.ended_at ? <li>Encerrada · {fmtTime(row.ended_at)}</li> : null}
        </ul>
        {row.message ? <div className="v2-note" style={{ marginTop: 6 }}>{row.message}</div> : null}
      </Section>
    </Drawer>
  );
}
