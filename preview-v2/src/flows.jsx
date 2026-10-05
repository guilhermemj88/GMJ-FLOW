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

// Exemplos de investigação (NÃO são vetores): apenas queries MATCH.
const EXPRESSION_EXAMPLES = [
  ['DNS reflection inbound', 'proto == udp and src_port == 53 and direction == inbound'],
  ['NTP reflection inbound', 'proto == udp and src_port == 123 and direction == inbound'],
  ['SSDP inbound', 'proto == udp and src_port == 1900 and direction == inbound'],
  ['Memcached inbound', 'proto == udp and src_port == 11211 and direction == inbound'],
  ['TCP SYN inbound', 'proto == tcp and tcp_flags contains syn and direction == inbound'],
  ['TCP SYN-ACK inbound', 'proto == tcp and tcp_flags contains syn and tcp_flags contains ack and direction == inbound'],
  ['ICMP inbound', 'proto == icmp and direction == inbound'],
];

const EMPTY = {
  range: 60, src_ip: '', dst_ip: '', src_port: '', dst_port: '', port: '',
  proto: '', decoder: '', tcp_flags: '', sensor: '', if_index: '', limit: 200, order_by: 'flow_time', order_dir: 'desc',
  expression: '',
};

function qs(form) {
  const params = new URLSearchParams();
  Object.entries(form).forEach(([key, value]) => {
    if (key === 'expression') return; // expressão só é enviada no modo Expressão
    if (value !== '' && value !== null && value !== undefined) params.set(key, String(value));
  });
  params.set('range_minutes', String(form.range));
  return params.toString();
}

// Modo Expressão: período/limite/ordenação + `expression` (seção MATCH).
// Se filtros legados também forem enviados, o backend combina com AND.
function expressionQs(form) {
  const params = new URLSearchParams();
  params.set('range_minutes', String(form.range));
  params.set('limit', String(form.limit));
  params.set('order_by', form.order_by);
  params.set('order_dir', form.order_dir);
  const expression = String(form.expression || '').trim();
  if (expression) params.set('expression', expression);
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

// Dicionário: consome GET /api/rule-language/catalog (nada duplicado no frontend).
// Mostra apenas os campos com match_allowed = true (seção MATCH do Flow Search).
function DictionaryDrawer({ onClose, onPick }) {
  const data = useApi('/api/rule-language/catalog');
  // Somente campos MATCH que realmente existem no Flow Search (linhas de flow_raw).
  const fields = (data.data?.fields || []).filter((item) => item.match_allowed && item.flow_search_allowed !== false);
  const columns = [
    {
      key: 'name',
      label: 'Campo',
      render: (r) => (
        <span className="mono">
          <b>{r.text_name || r.name}</b>
          {r.text_name && r.text_name !== r.name ? <small>{r.name}</small> : null}
        </span>
      ),
    },
    { key: 'aliases', label: 'Alias', render: (r) => (r.aliases?.length ? <span className="mono">{r.aliases.join(', ')}</span> : '—') },
    { key: 'description', label: 'Descrição' },
    { key: 'type', label: 'Tipo' },
    { key: 'operators', label: 'Operadores', render: (r) => <span className="mono">{(r.operators || []).join(' ') || '—'}</span> },
    { key: 'examples', label: 'Exemplos', render: (r) => (r.examples?.length ? <span className="mono">{r.examples[0]}</span> : '—') },
    { key: 'use', label: '', render: (r) => <button type="button" className="v2-mini" onClick={() => onPick(r.text_name || r.name)}>usar</button> },
  ];
  return (
    <div className="overlay" role="dialog" aria-modal="true" aria-label="Dicionário da linguagem de regras" onClick={onClose}>
      <aside className="drawer" style={{ width: 'min(980px, 96vw)' }} onClick={(event) => event.stopPropagation()}>
        <header>
          <div>
            <Badge tone="info">Dicionário</Badge>
            <h2>Campos do Flow Search</h2>
            <p>GET /api/rule-language/catalog · match_allowed = true e disponíveis no Flow Search · nenhuma lista duplicada no frontend</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fechar">×</button>
        </header>
        <section>
          {data.loading ? <Loading /> : data.error ? <ErrorBox message={data.error} /> : (
            <Table
              columns={columns}
              rows={fields}
              keyFor={(r) => r.name}
              empty={<EmptyState title="Catálogo indisponível" hint="O endpoint /api/rule-language/catalog responde no backend atual." />}
            />
          )}
        </section>
      </aside>
    </div>
  );
}

function Registros({ form, setForm, query, setQuery, onAskInterface }) {
  const data = useApi(`/api/flows/search?${query}`, { deps: [query] });
  const items = data.data?.items || [];
  const [downloading, setDownloading] = useState('');
  const [mode, setMode] = useState('filtros');
  const [validation, setValidation] = useState(null);
  const [validating, setValidating] = useState(false);
  const [dictionaryOpen, setDictionaryOpen] = useState(false);

  // Valida/preview (não executa query) e, quando solicitado, executa a busca.
  const validateExpression = async (execute) => {
    const expression = String(form.expression || '').trim();
    if (!expression) {
      setValidation({ valid: false, canonical_expression: null, errors: [{ code: 'EMPTY_EXPRESSION', message: 'Informe uma expressão (ex.: proto == udp and src_port == 53).' }] });
      return;
    }
    setValidating(true);
    try {
      const result = await api(`/api/flows/expression/validate?expression=${encodeURIComponent(expression)}`);
      setValidation(result);
      if (result.valid && execute) setQuery(expressionQs(form));
    } catch (err) {
      setValidation({ valid: false, canonical_expression: null, errors: [{ code: 'REQUEST_FAILED', message: err.message }] });
    } finally {
      setValidating(false);
    }
  };

  const pickFromDictionary = (token) => {
    const current = String(form.expression || '');
    const joiner = current && !/\s$/.test(current) ? ' ' : '';
    setForm({ ...form, expression: `${current}${joiner}${token} ` });
  };

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
          <div className="v2-mode">
            <button type="button" className={mode === 'filtros' ? 'v2-tab active' : 'v2-tab'} onClick={() => { setMode('filtros'); setValidation(null); }}>Filtros</button>
            <button type="button" className={mode === 'expressao' ? 'v2-tab active' : 'v2-tab'} onClick={() => setMode('expressao')}>Expressão</button>
          </div>
          <label className="v2-field"><span>Período</span>
            <select value={form.range} onChange={(e) => setForm({ ...form, range: Number(e.target.value) })}>
              {RANGES.map(([v, t]) => <option key={v} value={v}>{t}</option>)}
            </select>
          </label>
          {mode === 'filtros' ? (
            <>
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
            </>
          ) : null}
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
          <button type="button" className="primary" onClick={() => (mode === 'expressao' ? validateExpression(true) : setQuery(qs(form)))}>Buscar</button>
          <button type="button" className="control" onClick={() => { setForm(EMPTY); setQuery(qs(EMPTY)); }}>Limpar</button>
          <button type="button" className="control" disabled={downloading === 'csv'} onClick={() => download('csv')}>CSV (GET)</button>
          <button type="button" className="control" disabled={downloading === 'pdf'} onClick={() => download('pdf')}>PDF (GET)</button>
        </div>
      }
    >
      {mode === 'expressao' ? (
        <div className="v2-expression">
          <div className="v2-expression-bar">
            <input
              className="v2-expr-input mono"
              value={form.expression || ''}
              placeholder="proto == udp and src_port == 53 and direction == inbound"
              onChange={(e) => setForm({ ...form, expression: e.target.value })}
              onKeyDown={(e) => { if (e.key === 'Enter') validateExpression(true); }}
            />
            <button type="button" className="control" onClick={() => setDictionaryOpen(true)}>Dicionário</button>
            <button type="button" className="control" disabled={validating} onClick={() => validateExpression(false)}>{validating ? 'Validando…' : 'Validar'}</button>
            <button type="button" className="primary" disabled={validating} onClick={() => validateExpression(true)}>Executar busca</button>
          </div>
          <div className="v2-note">
            Somente a seção MATCH (linhas reais de flow_raw). Se filtros legados forem enviados junto, o backend combina com AND.
          </div>
          {validation ? (
            <div className="v2-expression-status">
              <Badge tone={validation.valid ? 'success' : 'warning'}>{validation.valid ? 'expressão válida' : 'expressão inválida'}</Badge>
              {validation.canonical_expression ? <span className="v2-note mono">canônica: {validation.canonical_expression}</span> : null}
              {(validation.fields || []).length ? <span className="v2-note mono">campos: {validation.fields.join(', ')}</span> : null}
              {(validation.errors || []).map((issue, index) => (
                <div key={`${issue.code}-${index}`} className="v2-note" style={{ color: 'var(--critical)' }}>
                  {issue.code}: {issue.message}{issue.suggestion ? ` — ${issue.suggestion}` : ''}
                </div>
              ))}
            </div>
          ) : null}
          <div className="v2-expression-examples">
            {EXPRESSION_EXAMPLES.map(([label, expr]) => (
              <button key={label} type="button" className="v2-mini" title={expr} onClick={() => { setForm({ ...form, expression: expr }); setValidation(null); }}>{label}</button>
            ))}
          </div>
        </div>
      ) : null}
      {dictionaryOpen ? <DictionaryDrawer onClose={() => setDictionaryOpen(false)} onPick={pickFromDictionary} /> : null}
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
