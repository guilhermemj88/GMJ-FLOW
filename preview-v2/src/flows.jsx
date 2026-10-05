import React, { useEffect, useState } from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Panel, Table,
  fmtBits, fmtNumber, fmtPps, fmtTime, token, useApi, api,
} from './shared.jsx';
import InterfaceRef from './interface-ref.jsx';

/**
 * BLOCO 3 — Flows V2 (somente leitura).
 *
 * Inspiração aprovada: C (Investigation + Rankings) + densidade de B + drawer/evidência de A.
 * REGISTROS DE FLOW = linhas individuais reais (GET /api/flows/search, server-side).
 * TOP FLOW = agregações (GET /api/flows/top). Nunca misturados na mesma tabela.
 * Export via GET (format=csv|pdf) — nenhum POST.
 */

const RANGES = [[15, '15 min'], [60, '60 min'], [240, '4 h'], [1440, '24 h']];
const TOP_TYPES = [
  ['src_ip', 'Origem'], ['dst_ip', 'Destino'], ['conversation', 'Conversa'],
  ['src_port', 'Porta origem'], ['dst_port', 'Porta destino'], ['proto', 'Protocolo'],
  ['input_if', 'Ingress ifIndex'], ['output_if', 'Egress ifIndex'], ['sensor', 'Sensor'],
];

const EMPTY = {
  range: 60, src_ip: '', dst_ip: '', src_port: '', dst_port: '', port: '',
  proto: '', decoder: '', tcp_flags: '', sensor: '', if_index: '', limit: 200, order_by: 'flow_time', order_dir: 'desc',
};

function qs(form) {
  const params = new URLSearchParams();
  Object.entries(form).forEach(([key, value]) => {
    if (value !== '' && value !== null && value !== undefined) params.set(key, String(value));
  });
  params.set('range_minutes', String(form.range));
  return params.toString();
}

function RateCell({ row }) {
  if (row.rate_status === 'unavailable_no_flow_duration') {
    return <span className="v2-chip muted" title={row.rate_note || ''}>Taxa indisponível</span>;
  }
  if (row.bits_s || row.packets_s) {
    return <span title={row.rate_note || ''}>{row.bits_s ? fmtBits(row.bits_s) : fmtPps(row.packets_s)}</span>;
  }
  return <span className="v2-muted">—</span>;
}

function FlowRow({ row }) {
  const exporter = row.exporter_ip || '';
  return (
    <tr>
      <td className="mono">{fmtTime(row.flow_time)}</td>
      <td>{row.sensor || '—'}<div className="v2-note mono">{exporter}</div></td>
      <td className="mono">{row.src_ip}:{row.src_port}</td>
      <td className="mono">{row.dst_ip}:{row.dst_port}</td>
      <td>{row.proto_name || row.proto}<div className="v2-note">{row.proto}</div></td>
      <td className="mono">{row.tcp_flags_name || '—'}</td>
      <td>
        <InterfaceRef exporterIp={exporter} ifIndex={row.input_if} name={row.input_if_name}
          alias={row.input_if_alias} descr={row.input_if_descr} source={row.input_interface_source}
          sensorId={row.input_interface_sensor_id} sensorName={row.input_interface_sensor_name} />
      </td>
      <td>
        <InterfaceRef exporterIp={exporter} ifIndex={row.output_if} name={row.output_if_name}
          alias={row.output_if_alias} descr={row.output_if_descr} source={row.output_interface_source}
          sensorId={row.output_interface_sensor_id} sensorName={row.output_interface_sensor_name} />
      </td>
      <td className="mono">{fmtNumber(row.bytes)}</td>
      <td className="mono">{fmtNumber(row.packets)}</td>
      <td className="mono">{fmtNumber(row.flow_count)}</td>
      <td><RateCell row={row} /></td>
    </tr>
  );
}

function Registros({ form, setForm, query, setQuery, onAskInterface }) {
  const data = useApi(`/api/flows/search?${query}`, { deps: [query] });
  const items = data.data?.items || [];
  const [downloading, setDownloading] = useState('');

  const download = async (format) => {
    setDownloading(format);
    try {
      const res = await fetch(`/api/flows/search?${query}&format=${format}`, {
        headers: token() ? { Authorization: `Bearer ${token()}` } : {},
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `gmj-flows.${format === 'csv' ? 'csv' : 'pdf'}`;
      link.click();
      URL.revokeObjectURL(url);
    } finally {
      setDownloading('');
    }
  };

  const field = (key, labelText, placeholder) => (
    <label className="v2-field"><span>{labelText}</span>
      <input value={form[key]} placeholder={placeholder || ''} onChange={(e) => setForm({ ...form, [key]: e.target.value })} />
    </label>
  );

  return (
    <Panel
      title="Registros de Flow"
      subtitle="Linhas individuais reais · busca server-side (CIDR suportado) · taxa real ou indisponível"
      badge={data.error ? 'Indisponível' : fmtNumber(items.length)}
      badgeTone={data.error ? 'warning' : 'info'}
      filters={
        <div className="v2-filters">
          <label className="v2-field"><span>Período</span>
            <select value={form.range} onChange={(e) => setForm({ ...form, range: Number(e.target.value) })}>
              {RANGES.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
            </select>
          </label>
          {field('src_ip', 'SRC IP/CIDR', '45.168.202.0/24')}
          {field('dst_ip', 'DST IP/CIDR', '203.0.113.9')}
          {field('src_port', 'SRC port', 'any')}
          {field('dst_port', 'DST port', '61810')}
          {field('port', 'Porta (src ou dst)')}
          <label className="v2-field"><span>Protocolo</span>
            <select value={form.proto} onChange={(e) => setForm({ ...form, proto: e.target.value })}>
              <option value="">todos</option><option value="udp">udp</option><option value="tcp">tcp</option>
              <option value="icmp">icmp</option><option value="17">17</option><option value="6">6</option>
            </select>
          </label>
          {field('decoder', 'Decoder', 'DNS, UDP…')}
          {field('tcp_flags', 'TCP flags', 'SYN')}
          {field('sensor', 'Sensor', 'NE8000-F1A-IMPLANTAR')}
          {field('if_index', 'Interface (ifIndex)', '90')}
          <label className="v2-field"><span>Limite</span>
            <select value={form.limit} onChange={(e) => setForm({ ...form, limit: Number(e.target.value) })}>
              {[50, 200, 500, 1000, 2000].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <label className="v2-field"><span>Ordenar</span>
            <select value={form.order_by} onChange={(e) => setForm({ ...form, order_by: e.target.value })}>
              {['flow_time', 'bytes', 'packets', 'flows'].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <label className="v2-field"><span>Direção</span>
            <select value={form.order_dir} onChange={(e) => setForm({ ...form, order_dir: e.target.value })}>
              <option value="desc">desc</option><option value="asc">asc</option>
            </select>
          </label>
          <button type="button" className="primary" onClick={() => setQuery(qs(form))}>Buscar</button>
          <button type="button" className="control" onClick={() => { setForm(EMPTY); setQuery(qs(EMPTY)); }}>Limpar</button>
          <button type="button" className="control" disabled={downloading === 'csv'} onClick={() => download('csv')}>CSV (GET)</button>
          <button type="button" className="control" disabled={downloading === 'pdf'} onClick={() => download('pdf')}>PDF (GET)</button>
        </div>
      }
    >
      {data.error ? <ErrorBox message={data.error} /> : null}
      {data.loading ? <Loading /> : (
        <div className="v2-dense-wrap">
          <table className="v2-dense">
            <thead>
              <tr>
                <th>Horário</th><th>Sensor / exporter</th><th>Origem</th><th>Destino</th><th>Proto</th>
                <th>TCP flags</th><th>Ingress</th><th>Egress</th><th>Bytes</th><th>Pacotes</th><th>Flows</th><th>Taxa</th>
              </tr>
            </thead>
            <tbody>
              {items.length ? items.map((row) => (
                <FlowRow key={`${row.flow_time}-${row.src_ip}-${row.dst_ip}-${row.src_port}-${row.dst_port}`} row={row} />
              )) : (
                <tr><td colSpan={12}><EmptyState title="Nenhum registro" hint="Ajuste os filtros ou amplie o período. A busca é server-side." /></td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      <div className="v2-note" style={{ marginTop: 8 }}>
        Janela: {data.data?.start ? fmtTime(data.data.start) : '—'} → {data.data?.end ? fmtTime(data.data.end) : '—'} ·
        {' '}interface resolvida por (exporter, ifIndex) — o ifIndex cru nunca é escondido · taxa só quando o flow tem duração real.
        {onAskInterface ? ' Clique em “ver” numa interface para abrir o inventário filtrado.' : ''}
      </div>
    </Panel>
  );
}

function TopFlow({ form, setForm, applyFromTop }) {
  const [topType, setTopType] = useState('dst_ip');
  const [topLimit, setTopLimit] = useState(10);
  const [orderBy, setOrderBy] = useState('bits_s');
  const query = `top_type=${topType}&range_minutes=${form.range}&limit=${topLimit}&order_by=${orderBy}`;
  const data = useApi(`/api/flows/top?${query}`, { deps: [query] });
  const items = data.data?.items || [];

  return (
    <Panel
      title="Top Flow"
      subtitle="Agregações reais na janela · “Investigar” leva os valores comprovados para Registros de Flow"
      badge={data.error ? 'Indisponível' : fmtNumber(items.length)}
      badgeTone={data.error ? 'warning' : 'info'}
      filters={
        <div className="v2-filters">
          <label className="v2-field"><span>Dimensão</span>
            <select value={topType} onChange={(e) => setTopType(e.target.value)}>
              {TOP_TYPES.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
            </select>
          </label>
          <label className="v2-field"><span>Janela</span>
            <select value={form.range} onChange={(e) => setForm({ ...form, range: Number(e.target.value) })}>
              {RANGES.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
            </select>
          </label>
          <label className="v2-field"><span>Top N</span>
            <select value={topLimit} onChange={(e) => setTopLimit(Number(e.target.value))}>
              {[10, 20, 50, 100].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <label className="v2-field"><span>Ordenar por</span>
            <select value={orderBy} onChange={(e) => setOrderBy(e.target.value)}>
              {['bits_s', 'packets_s', 'bytes', 'packets', 'flows'].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
        </div>
      }
    >
      {data.error ? <ErrorBox message={data.error} /> : null}
      {data.loading ? <Loading /> : (
        <Table
          columns={[
            { key: 'key', label: 'Valor agregado', render: (r) => <b className="mono">{r.key || r[topType] || '—'}</b> },
            { key: 'bits_s', label: 'Bits/s', render: (r) => (r.bits_s != null ? fmtBits(r.bits_s) : '—') },
            { key: 'packets_s', label: 'Pacotes/s', render: (r) => (r.packets_s != null ? fmtPps(r.packets_s) : '—') },
            { key: 'bytes', label: 'Bytes', render: (r) => fmtNumber(r.bytes) },
            { key: 'packets', label: 'Pacotes', render: (r) => fmtNumber(r.packets) },
            { key: 'flows', label: 'Flows', render: (r) => fmtNumber(r.flows) },
            { key: 'percent_total', label: '% total', render: (r) => (r.percent_total != null ? `${fmtNumber(r.percent_total, 1)}%` : '—') },
            { key: 'duration_seconds', label: 'Duração', render: (r) => (r.duration_seconds ? `${fmtNumber(r.duration_seconds)} s` : '—') },
            { key: 'last_seen', label: 'Última', render: (r) => (r.last_seen ? fmtTime(r.last_seen) : '—') },
            {
              key: 'investigar',
              label: '',
              render: (r) => <button type="button" className="v2-mini" onClick={() => applyFromTop(topType, r)}>Investigar</button>,
            },
          ]}
          rows={items}
          keyFor={(r, i) => `${r.key || i}`}
          empty={<EmptyState title="Sem agregação na janela" hint="Sem tráfego agregado para esta dimensão no período." />}
        />
      )}
      <div className="v2-note" style={{ marginTop: 8 }}>
        Agregação preserva sample-rate, bytes, pacotes, flows e percent_total do backend. “Investigar” só preenche
        filtros que a própria linha comprova (ex.: destino, porta, protocolo, sensor e a janela) — nada é inventado.
      </div>
    </Panel>
  );
}

export default function Flows({ focus, onNavigate }) {
  const [tab, setTab] = useState('registros');
  const [form, setForm] = useState(EMPTY);
  const [query, setQuery] = useState(() => qs(EMPTY));
  const [handoff, setHandoff] = useState(null);

  // Cross-link real: Anomalias / Peak Hunter / Interfaces podem abrir Flows com
  // filtros JÁ comprovados pelos dados (nunca inventamos src/dst).
  useEffect(() => {
    if (!focus) return;
    const next = { ...EMPTY };
    const applied = [];
    if (focus.src_ip) { next.src_ip = String(focus.src_ip); applied.push('src_ip'); }
    if (focus.dst_ip) { next.dst_ip = String(focus.dst_ip); applied.push('dst_ip'); }
    if (focus.dst_port) { next.dst_port = String(focus.dst_port); applied.push('dst_port'); }
    if (focus.src_port) { next.src_port = String(focus.src_port); applied.push('src_port'); }
    if (focus.protocol) { next.proto = String(focus.protocol).toLowerCase(); applied.push('proto'); }
    if (focus.sensor) { next.sensor = String(focus.sensor); applied.push('sensor'); }
    if (focus.ifIndex) { next.if_index = String(focus.ifIndex); applied.push('if_index'); }
    if (focus.range_minutes) { next.range = Number(focus.range_minutes) || 60; }
    if (!applied.length) return;
    setForm(next);
    setQuery(qs(next));
    setTab('registros');
    setHandoff({ dimension: focus.source || 'cross-link', key: applied.join(', '), applied, window: `${next.range} min` });
  }, [focus]);

  const applyFromTop = (topType, row) => {
    const key = row?.key || '';
    const next = { ...EMPTY, range: form.range };
    const applied = [];
    if (topType === 'src_ip' && key) { next.src_ip = key; applied.push('src_ip'); }
    else if (topType === 'dst_ip' && key) { next.dst_ip = key; applied.push('dst_ip'); }
    else if (topType === 'src_port' && key) { next.src_port = key; applied.push('src_port'); }
    else if (topType === 'dst_port' && key) { next.dst_port = key; applied.push('dst_port'); }
    else if (topType === 'proto' && key) { next.proto = String(key).toLowerCase(); applied.push('proto'); }
    else if ((topType === 'input_if' || topType === 'output_if') && key) { next.if_index = key; applied.push('if_index'); }
    else if (topType === 'sensor' && key) { next.sensor = key; applied.push('sensor'); }
    setForm(next);
    setQuery(qs(next));
    setTab('registros');
    setHandoff({ dimension: topType, key, applied, window: `${form.range} min` });
  };

  const askInterface = (ref) => {
    const next = { ...EMPTY, range: form.range };
    if (ref.ifIndex) next.if_index = String(ref.ifIndex);
    if (ref.sensorName) next.sensor = ref.sensorName;
    if (ref.exporterIp) next.sensor = next.sensor || ref.exporterIp;
    setForm(next);
    setQuery(qs(next));
    setTab('registros');
  };

  return (
    <div className="page">
      <div className="v2-tabs">
        <button className={tab === 'registros' ? 'v2-tab on' : 'v2-tab'} onClick={() => setTab('registros')}>Registros de Flow</button>
        <button className={tab === 'top' ? 'v2-tab on' : 'v2-tab'} onClick={() => setTab('top')}>Top Flow</button>
        <span className="v2-tab-spacer" />
        <Badge tone="muted">registros = linhas reais</Badge>
        <Badge tone="muted">top = agregação</Badge>
      </div>
      <div className="v2-readonly-note">
        <Badge tone="critical">SOMENTE LEITURA</Badge>
        <span>Busca e export são GET (server-side). Nenhuma operação de escrita é executada pela preview.</span>
      </div>
      {handoff ? (
        <div className="v2-handoff">
          <b>Handoff do Top Flow</b>
          <span>dimensão <b>{handoff.dimension}</b> = <span className="mono">{handoff.key}</span> · janela {handoff.window} ·
            {' '}filtros aplicados: {handoff.applied.length ? handoff.applied.join(', ') : 'nenhum (a dimensão não é mapeável com segurança)'}
          </span>
          <button type="button" className="v2-mini" onClick={() => setHandoff(null)}>ocultar</button>
        </div>
      ) : null}
      {tab === 'registros'
        ? <Registros form={form} setForm={setForm} query={query} setQuery={setQuery} onAskInterface={askInterface} />
        : <TopFlow form={form} setForm={setForm} applyFromTop={applyFromTop} />}
    </div>
  );
}
