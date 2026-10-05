import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import './preview.css';
import {
  Badge, ErrorBox, Loading, Panel, Table,
  api, setToken, token, useApi, hasPermission, ENV_LABEL,
  fmtBits, fmtPps, fmtTime, statusTone,
} from './shared.jsx';
import Threat from './threat.jsx';
import Anomalias from './anomalies.jsx';
import Mitigation from './mitigation.jsx';
import Bgp from './bgp.jsx';
import Alerts from './alerts.jsx';
import PeakHunter from './peak.jsx';
import VectorsPage from './vectors.jsx';
import FlowsPage from './flows.jsx';
import InterfacesPage from './interfaces.jsx';
import SensorsPage from './sensors.jsx';
import { MediaPage, CodecsPage, DatabasePage, SystemPage } from './platform.jsx';
import { GlobalMapPage, ZonesPage, PrefixesPage, CgnatPage } from './geo.jsx';
import UsersPage from './users.jsx';

function seriesLatest(seriesList) {
  const list = Array.isArray(seriesList) ? seriesList : [];
  let total = 0;
  let any = false;
  for (const s of list) {
    const points = Array.isArray(s?.points) ? s.points : [];
    const last = points[points.length - 1];
    const v = Number(last?.value);
    if (Number.isFinite(v)) { total += v; any = true; }
  }
  return any ? total : null;
}

const PROTOCOL_COLORS = {
  TCP: '#22d3ee',
  'TCP+SYN': '#38bdf8',
  UDP: '#a78bfa',
  ICMP: '#fbbf24',
  GRE: '#34d399',
  ESP: '#f472b6',
  OTHER: '#94a3b8',
};
const PROTOCOL_FALLBACK = ['#22d3ee', '#38bdf8', '#a78bfa', '#34d399', '#fbbf24', '#f472b6', '#94a3b8'];
// Ordem canonica da legenda: uma entrada por PROTOCOLO (direcao nao entra na
// legenda). Protocolos fora da lista ficam no fim, em ordem alfabetica.
const PROTOCOL_ORDER = ['TCP', 'UDP', 'ICMP', 'GRE', 'ESP', 'OTHER', 'TCP+SYN'];

function trafficProtocol(name) {
  return String(name || '').replace(/\s*(upload|download)\s*/gi, ' ').replace(/\s+/g, ' ').trim() || String(name || '');
}

function trafficDirection(name) {
  return /upload/i.test(String(name || '')) ? 'upload' : 'download';
}

function trafficColor(protocol, index) {
  return PROTOCOL_COLORS[protocol] || PROTOCOL_FALLBACK[index % PROTOCOL_FALLBACK.length];
}

function TrafficChart({ series }) {
  const list = Array.isArray(series) ? series.filter((s) => s?.points?.length) : [];
  if (!list.length) return <div className="subtle" style={{ padding: '14px 16px' }}>Sem série disponível.</div>;
  const W = 900, H = 240;

  const protocols = list.map((s) => trafficProtocol(s.name));
  const directions = list.map((s) => trafficDirection(s.name));

  // Cor por PROTOCOLO: upload e download do mesmo protocolo compartilham a cor.
  const colorByProtocol = new Map();
  list.forEach((s, si) => {
    if (!colorByProtocol.has(protocols[si])) colorByProtocol.set(protocols[si], trafficColor(protocols[si], si));
  });
  const colorOf = (si) => colorByProtocol.get(protocols[si]);
  const legendEntries = [...colorByProtocol.entries()].sort(([left], [right]) => {
    const rank = (name) => {
      const position = PROTOCOL_ORDER.indexOf(name);
      return position === -1 ? PROTOCOL_ORDER.length : position;
    };
    const diff = rank(left) - rank(right);
    return diff !== 0 ? diff : left.localeCompare(right);
  });

  // Alinha todas as séries no mesmo eixo temporal (comprimento = maior série).
  const n = Math.max(...list.map((s) => s.points.length));
  const values = list.map((s) => Array.from({ length: n }, (_, i) => {
    const v = Number(s.points[i]?.value);
    return Number.isFinite(v) && v > 0 ? v : 0;
  }));

  // DUAS pilhas a partir do zero: download cresce para cima, upload para baixo.
  const zeros = () => new Array(n).fill(0);
  let accDown = zeros(), accUp = zeros();
  const layers = list.map((s, si) => {
    if (directions[si] === 'upload') {
      const base = accUp;
      const top = base.map((v, i) => v - values[si][i]);
      accUp = top;
      return { base, top };
    }
    const base = accDown;
    const top = base.map((v, i) => v + values[si][i]);
    accDown = top;
    return { base, top };
  });

  // Escala ÚNICA e simétrica: preserva a relação real de magnitude entre os sentidos.
  const maxDown = Math.max(0, ...accDown);
  const maxUp = Math.max(0, ...accUp.map((v) => Math.abs(v)));
  const max = Math.max(1, maxDown, maxUp);
  const zero = H / 2;
  const x = (i) => (i / Math.max(1, n - 1)) * W;
  const y = (v) => zero - (Number(v) / max) * (zero - 14);

  const areaPath = ({ base, top }) => {
    const forward = top.map((v, i) => `${x(i)},${y(v)}`);
    const backward = [];
    for (let i = n - 1; i >= 0; i -= 1) backward.push(`${x(i)},${y(base[i])}`);
    return `M ${forward.join(' L ')} L ${backward.join(' L ')} Z`;
  };

  return (
    <div className="traffic-chart">
      <div className="chart-scale">
        <span>{fmtBits(max)}</span>
        <span>DOWNLOAD</span>
        <span>0</span>
        <span>UPLOAD</span>
        <span>{fmtBits(max)}</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-label="Gráfico de tráfego (download acima, upload abaixo)">
        <line x1="0" y1={zero} x2={W} y2={zero} stroke="#3b4a57" strokeWidth="1" strokeDasharray="4 4" />
        {list.map((s, si) => (
          <path key={s.name || si} d={areaPath(layers[si])}
            fill={colorOf(si)} fillOpacity="0.78"
            stroke={colorOf(si)} strokeWidth="1" strokeLinejoin="round">
            <title>{`${protocols[si]} · ${directions[si]} · ${fmtBits(Math.abs(layers[si].top[n - 1] - layers[si].base[n - 1]))}`}</title>
          </path>
        ))}
      </svg>
      <div className="chart-legend">
        {legendEntries.map(([protocol, color]) => (
          <span key={protocol}><i className="legend-dot" style={{ background: color }} />{protocol}</span>
        ))}
      </div>
    </div>
  );
}

function Login({ onSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      const data = await api('/api/auth/login', { method: 'POST', body: { username, password } });
      if (!data?.token) throw new Error('Resposta de login sem token.');
      setToken(data.token);
      onSuccess(data.user);
    } catch (err) { setError(err.message); }
    finally { setBusy(false); }
  };
  return (
    <div className="login-screen">
      <div className="login-card">
        <div className="brand"><div className="brand-mark">G</div><div><b>GMJ-FLOW</b><small>SHADOW / STAGING PREVIEW</small></div></div>
        <div className="preview-env-banner"><i className="status-dot critical pulse" /> {ENV_LABEL}</div>
        <h1>Entrar na preview</h1>
        <p className="subtle">Mesmo backend de produção, em modo somente leitura. Nenhuma ação de escrita é permitida.</p>
        <form onSubmit={submit}>
          <label>Usuário<input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" /></label>
          <label>Senha<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" /></label>
          {error ? <div className="login-error">{error}</div> : null}
          <button className="primary" type="submit" disabled={busy || !username || !password}>{busy ? 'Entrando…' : 'Entrar'}</button>
        </form>
      </div>
    </div>
  );
}

function Sidebar({ page, setPage, user }) {
  const groups = [
    { label: 'Visão geral', items: [['Dashboard', 'dashboard'], ['Flows', 'flows'], ['Sensores', 'sensors'], ['Interfaces', 'interfaces'], ['Mapa Global', 'gmaps'], ['Clientes / Zonas', 'zones']] },
    { label: 'Segurança', items: [['Anomalias', 'anomalies'], ['Peak Hunter', 'peak'], ['Threat Intelligence', 'threat'], ['Alertas', 'alerts'], ['Mitigação', 'mitigation'], ['BGP / Conectores', 'bgp'], ['Vetores de Ataque', 'vectors']] },
    { label: 'Rede / Classificação', items: [['Codecs', 'codecs'], ['Prefixos', 'prefixes'], ['CGNAT', 'cgnat']] },
    { label: 'Integrações', items: [['Mídia', 'media']] },
    { label: 'Plataforma', items: [['Banco', 'database'], ['Sistema', 'system']] },
    { label: 'Administração', items: [['Usuários e Acessos', 'users']] },
  ];
  // Gate por permissão: a rota só aparece com `users.view` (fonte: /api/auth/me).
  const visibleGroups = groups
    .map((group) => ({
      ...group,
      items: group.items.filter(([, id]) => id !== 'users' || hasPermission(user, 'users.view')),
    }))
    .filter((group) => group.items.length > 0);
  return (
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark">G</div><div><b>GMJ-FLOW</b><small>NETWORK CONTROL PLANE</small></div></div>
      <div className="preview-env-banner"><i className="status-dot critical pulse" /> {ENV_LABEL}</div>
      {visibleGroups.map((group) => (
        <div className="nav-group" key={group.label}>
          <p>{group.label}</p>
          {group.items.map(([label, id]) => (
            <button key={id} className={page === id ? 'nav-item active' : 'nav-item'} onClick={() => setPage(id)}><span>{label}</span></button>
          ))}
        </div>
      ))}
      <div className="sidebar-footer">
        <div><span>Usuário</span><b>{user?.username || '—'}</b></div>
        <div><span>Perfil</span><b>{user?.role || '—'}</b></div>
        <small>Somente leitura · proxy bloqueia escrita</small>
      </div>
    </aside>
  );
}

function Header({ page, onLogout }) {
  const names = {
    dashboard: ['Dashboard operacional', 'Resumo de produção em tempo quase real'],
    anomalies: ['Anomalias', 'Fila e histórico de eventos reais'],
    mitigation: ['Mitigação', 'Execuções reais do orquestrador'],
    bgp: ['BGP / Conectores', 'Conectores, anúncios e perfis reais'],
    threat: ['Threat Intelligence', 'Inteligência externa, eventos, campanhas e decisões'],
    peak: ['Peak Hunter', 'Picos recentes persistidos'],
    vectors: ['Vetores de Ataque', 'Detection engineering - vetores, templates, regras e whitelist reais'],
    interfaces: ['Interfaces', 'Inventario de interfaces por (exporter, ifIndex) - nomes, monitoracao e sample-rate'],
    alerts: ['Alertas', 'Central operacional agregadora — anomalias, mitigações, BGP e coletores'],
    flows: ['Flows', 'Top flows e telemetria agregada'],
    media: ['Mídia', 'Integrações de notificação · webhook / Telegram via n8n'],
    codecs: ['Codecs', 'Classificação de flows por protocolo, portas e papéis'],
    gmaps: ['Mapa Global', 'Tráfego / fluxos geográficos agregados · node = cidade/país/ASN/IP'],
    zones: ['Clientes / Zonas', 'Zonas canônicas (ip_zones) e seus prefixos'],
    prefixes: ['Prefixos', 'Prefixos por zona (ip_zone_prefixes) — tabela legacy não é usada'],
    cgnat: ['CGNAT', 'Pools, mapeamentos e imports · resolução só determinística'],
    database: ['Banco de Dados', 'Saúde, volume, retenção e tabelas principais'],
    system: ['Sistema', 'Recursos, disk guard, cache e containers'],
    sensors: ['Sensores', 'Coletores e ingestão reais'],
    users: ['Usuários e Acessos', 'Contas, perfis e permissões reais · listagem somente leitura (P0-A)'],
  };
  const [title, subtitle] = names[page] || names.dashboard;
  return (
    <header className="operational-header">
      <div><h1>{title}</h1><p>{subtitle}</p></div>
      <div className="header-actions">
        <Badge tone="critical" pulse>{ENV_LABEL}</Badge>
        <button className="control" onClick={onLogout}>Sair</button>
      </div>
    </header>
  );
}

function RankingCard({ title, subtitle, items, loading, error, labelFor, titleFor, valueFor, pctFor, expandable = true }) {
  const [open, setOpen] = useState(false);
  const list = Array.isArray(items) ? items : [];
  const visible = open ? list : list.slice(0, 5);
  return (
    <div className="ranking-card">
      <div className="ranking-head"><div><b>{title}</b><span>{subtitle}</span></div>{error ? <Badge tone="warning">Indisponível</Badge> : <Badge tone="info">{list.length}</Badge>}</div>
      {loading ? <Loading /> : error ? <ErrorBox message={error} /> : (
        <>
          <div className="ranking-rows">
            {visible.length === 0 ? <div className="subtle" style={{ padding: '8px 10px' }}>Sem dados.</div> : visible.map((item, i) => (
              <div className="ranking-row" key={i}>
                <span className="rk">{i + 1}</span>
                <span className="rk-key" title={titleFor ? titleFor(item) : labelFor(item)}>{labelFor(item)}</span>
                <span className="rk-val">{valueFor(item)}</span>
                <span className="rk-pct">{pctFor(item, list)}</span>
              </div>
            ))}
          </div>
          {expandable && list.length > 5 ? (
            <button className="ranking-more" onClick={() => setOpen(!open)}>{open ? 'recolher' : 'ver mais'} →</button>
          ) : null}
        </>
      )}
    </div>
  );
}

function RankingCardFetch({ def }) {
  const { data, loading, error } = useApi(def.endpoint);
  const items = def.pick ? def.pick(data) : data?.items;
  return (
    <RankingCard
      title={def.title}
      subtitle="últimos 30 min"
      items={items || []}
      loading={loading}
      error={error}
      labelFor={def.label}
      titleFor={def.titleFor}
      valueFor={def.value}
      pctFor={def.pct}
    />
  );
}

function sharePct(item, list) {
  const total = (list || []).reduce((sum, row) => sum + (Number(row.bps) || 0), 0);
  if (!total) return '—';
  return `${(((Number(item.bps) || 0) / total) * 100).toFixed(1)}%`;
}

const RANKING_DEFS = [
  { key: 'asn_src', title: 'Top AS origem', endpoint: '/api/tops/asn-src?limit=25&range_minutes=30', label: (r) => r.asn || '—', titleFor: (r) => `${r.asn || ''} · ${r.org_name || r.display_name || ''}`.trim(), value: (r) => fmtBits(r.bps), pct: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
  { key: 'asn_dst', title: 'Top AS destino', endpoint: '/api/tops/asn-dst?limit=25&range_minutes=30', label: (r) => r.asn || '—', titleFor: (r) => `${r.asn || ''} · ${r.org_name || r.display_name || ''}`.trim(), value: (r) => fmtBits(r.bps), pct: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
  { key: 'src_ip', title: 'Top IP origem', endpoint: '/api/tops/src-ip?limit=25&range_minutes=30', label: (r) => r.ip || '—', value: (r) => fmtBits(r.bps), pct: sharePct },
  { key: 'dst_ip', title: 'Top IP destino', endpoint: '/api/tops/dst-ip?limit=25&range_minutes=30', label: (r) => r.ip || '—', value: (r) => fmtBits(r.bps), pct: sharePct },
  { key: 'conversations', title: 'Top conversations', endpoint: '/api/dashboard/top-conversations?limit=25&range_minutes=30', label: (r) => `${r.src_ip || '—'} → ${r.dst_ip || '—'}`, value: (r) => fmtBits(r.bits_s), pct: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
  { key: 'ports', title: 'Top portas', endpoint: '/api/tops/ports?limit=25&range_minutes=30', label: (r) => `${r.proto || '—'}/${r.port ?? '—'}`, value: (r) => fmtBits(r.bps), pct: sharePct },
  { key: 'protocols', title: 'Top protocolos', endpoint: '/api/tops/protocols?limit=25&range_minutes=30', label: (r) => r.proto || '—', value: (r) => fmtBits(r.bps), pct: sharePct },
  { key: 'syn', title: 'Top SYN', endpoint: '/api/dashboard/top-syn?limit=25&range_minutes=30', label: (r) => r.ip, value: (r) => fmtPps(r.packets_s), pct: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
  { key: 'interfaces', title: 'Interfaces relevantes', endpoint: '/api/flows/top?top_type=interfaces&limit=25&range_minutes=30', label: (r) => r.key, value: (r) => fmtBits(r.bits_s), pct: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
  {
    key: 'ext_asn_download', title: 'ASN externo · download',
    endpoint: '/api/dashboard/directional-analytics?range_minutes=30&limit=25',
    pick: (d) => d?.external_asn_download?.items,
    label: (r) => r.asn || '—', titleFor: (r) => `${r.asn || '—'} · ${r.org_name || r.display_name || ''}`.trim(),
    value: (r) => fmtBits(r.bps), pct: sharePct,
  },
  {
    key: 'ext_asn_upload', title: 'ASN externo · upload',
    endpoint: '/api/dashboard/directional-analytics?range_minutes=30&limit=25',
    pick: (d) => d?.external_asn_upload?.items,
    label: (r) => r.asn || '—', titleFor: (r) => `${r.asn || '—'} · ${r.org_name || r.display_name || ''}`.trim(),
    value: (r) => fmtBits(r.bps), pct: sharePct,
  },
  {
    key: 'local_ip_download', title: 'IP local · download',
    endpoint: '/api/dashboard/directional-analytics?range_minutes=30&limit=25',
    pick: (d) => d?.local_ip_download?.items,
    label: (r) => r.ip || '—',
    value: (r) => fmtBits(r.bps), pct: sharePct,
  },
  {
    key: 'local_ip_upload', title: 'IP local · upload',
    endpoint: '/api/dashboard/directional-analytics?range_minutes=30&limit=25',
    pick: (d) => d?.local_ip_upload?.items,
    label: (r) => r.ip || '—',
    value: (r) => fmtBits(r.bps), pct: sharePct,
  },
];

function Dashboard() {
  const ops = useApi('/api/ops/summary');
  const bits = useApi('/api/dashboard/series?metric=bits_s&group_by=protocol&range_minutes=30');
  const pps = useApi('/api/dashboard/series?metric=packets_s&group_by=total&range_minutes=30');
  const connectors = useApi('/api/bgp/connectors');
  const activeAnomalies = useApi('/api/anomalies/active?limit=20');
  const announcements = useApi('/api/bgp/announcements?status=advertised&limit=20');

  const s = ops.data || {};
  const connList = connectors.data?.items || [];
  const anomList = activeAnomalies.data?.items || [];
  const annList = announcements.data?.items || [];
  const curBits = seriesLatest(bits.data?.series || []);
  const curPps = seriesLatest(pps.data?.series || []);
  const criticalAnomaly = anomList.find((a) => String(a.severity).toLowerCase() === 'critical');
  const ready = connList.filter((c) => String(c.bgp_state).toLowerCase() === 'established').length;

  return (
    <div className="main-content">
      {criticalAnomaly ? (
        <div className="alert-banner">
          <i className="status-dot critical pulse" />
          <div><b>ALERTA CRÍTICO</b><span>{criticalAnomaly.decoder || criticalAnomaly.vector_name || 'Anomalia crítica'} em <code>{criticalAnomaly.target_ip || criticalAnomaly.target_cidr || '—'}</code></span></div>
          <code>{fmtBits(criticalAnomaly.peak_value)} / {fmtPps(criticalAnomaly.peak_value)}</code>
        </div>
      ) : (
        <div className="alert-banner ok"><i className="status-dot success pulse" /><div><b>SEM ALERTA CRÍTICO</b><span>Nenhuma anomalia crítica ativa no momento.</span></div></div>
      )}

      <div className="filter-bar">
        <div className="filter-summary"><b>Filtros do Dashboard</b><span>Todos os IPs · dados reais</span><Badge tone="info">Somente leitura</Badge></div>
      </div>

      <div className="metrics-grid">
        <div className="metric-card rail-cyan"><span>Tráfego observado</span><strong>{curBits != null ? fmtBits(curBits) : '—'}</strong><small className="cyan">último bucket · 30 min</small></div>
        <div className="metric-card rail-warning"><span>Pacotes por segundo</span><strong>{curPps != null ? fmtPps(curPps) : '—'}</strong><small className="warning">último bucket · 30 min</small></div>
        <div className="metric-card rail-critical"><span>Anomalias abertas</span><strong>{s.active_anomalies ?? '—'}</strong><small className="critical">{s.active_critical ?? 0} crítica(s)</small></div>
        <div className="metric-card rail-success"><span>FlowSpec ativo</span><strong>{s.active_bgp_announcements ?? '—'}</strong><small className="success">BGP confirmado</small></div>
      </div>

      <div className="dashboard-grid">
        <Panel title="Telemetria de tráfego" subtitle="Bits/s por protocolo · últimos 30 min" badge="dados reais">
          {bits.loading ? <Loading /> : bits.error ? <ErrorBox message={bits.error} /> : <TrafficChart series={bits.data?.series || []} />}
        </Panel>
        <div className="data-panel bgp-health">
          <div className="panel-title"><div><b>Saúde BGP / FlowSpec</b><span>Prontidão para anunciar</span></div><Badge tone={connectors.error ? 'warning' : 'success'}>{connectors.error ? 'Indisponível' : `${ready}/${connList.length}`}</Badge></div>
          {connectors.loading ? <Loading /> : connectors.error ? <ErrorBox message={connectors.error} /> : (
            <>
              <div className="health-score"><b>{ready} / {connList.length}</b><span>BGP Established · FlowSpec disponível</span></div>
              {connList.map((item) => (
                <div className="peer-line" key={item.id}><i className={`status-dot ${String(item.bgp_state).toLowerCase() === 'established' ? 'success' : 'warning'}`} /><div><b>{item.name}</b><code>{item.peer_ip || '—'}</code></div><Badge tone={statusTone(item.bgp_state)}>{item.bgp_state || '—'}</Badge></div>
              ))}
            </>
          )}
        </div>
      </div>

      <div className="dashboard-grid lower">
        <Panel title="Fila operacional de anomalias" subtitle="Prioridade por impacto e confiança" badge={activeAnomalies.error ? 'Indisponível' : activeAnomalies.data?.total ?? anomList.length} badgeTone={activeAnomalies.error ? 'warning' : 'info'}>
          {activeAnomalies.loading ? <Loading /> : activeAnomalies.error ? <ErrorBox message={activeAnomalies.error} /> : (
            <Table
              columns={[
                { key: 'severity', label: 'Sev.', render: (r) => <Badge tone={r.severity === 'critical' ? 'critical' : r.severity === 'warning' ? 'warning' : 'info'}>{r.severity}</Badge> },
                { key: 'id', label: 'ID' },
                { key: 'target_ip', label: 'Alvo' },
                { key: 'decoder', label: 'Detector' },
                { key: 'peak_value', label: 'Pico', render: (r) => `${r.peak_value ?? '—'} ${r.metric_unit || ''}`.trim() },
                { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
              ]}
              rows={anomList}
              keyFor={(r) => r.id}
            />
          )}
        </Panel>
        <div className="response-stack">
          <div className="stack-head"><b>Resposta ativa</b><span>{announcements.error ? 'Indisponível' : `${annList.length} anúncios FlowSpec`}</span></div>
          {announcements.loading ? <Loading /> : announcements.error ? <ErrorBox message={announcements.error} /> : annList.length === 0 ? <div className="data-panel" style={{ padding: '14px' }}><span className="subtle">Nenhuma resposta FlowSpec ativa.</span></div> : annList.map((item) => (
            <div className="mitigation-card" key={item.id}>
              <div className="mitigation-top"><div><Badge tone="success" pulse>FlowSpec ativo</Badge><h3>{item.action || '—'}</h3><code>{item.target_prefix || '—'}</code></div></div>
              <div className="mitigation-meta"><span>{item.connector_name || '—'}</span><span>{item.response_profile_name || '—'}</span></div>
              <div className="mitigation-bottom"><Badge tone={statusTone(item.status)}>{item.status || '—'}</Badge><span className="subtle">atualizado {fmtTime(item.updated_at)}</span></div>
            </div>
          ))}
        </div>
      </div>

      <div className="rankings-section">
        <div className="rankings-title"><div><h2>Rankings operacionais</h2><span>Camada de investigação · últimos 30 min</span></div><Badge tone="info">dados reais</Badge></div>
        <div className="rankings-grid">
          {RANKING_DEFS.map((def) => <RankingCardFetch key={def.key} def={def} />)}
        </div>
      </div>
    </div>
  );
}


function Sensors() {
  const sensors = useApi('/api/sensors');
  const ingestion = useApi('/api/collectors/ingestion/status');
  const list = sensors.data?.items || [];
  const ingList = ingestion.data?.items || [];
  return (
    <div className="main-content">
      <Panel title="Sensores" subtitle="Coletores e interfaces reais" badge={sensors.error ? 'Indisponível' : list.length} badgeTone={sensors.error ? 'warning' : 'success'}>
        {sensors.loading ? <Loading /> : sensors.error ? <ErrorBox message={sensors.error} /> : (
          <Table
            columns={[
              { key: 'id', label: 'ID' },
              { key: 'name', label: 'Nome' },
              { key: 'exporter_ip', label: 'Exporter' },
              { key: 'listener_port', label: 'Porta' },
              { key: 'flow_protocol', label: 'Protocolo' },
              { key: 'active', label: 'Ativo', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'Sim' : 'Não'}</Badge> },
              { key: 'interfaces', label: 'Interfaces', render: (r) => (r.interfaces || []).length },
            ]}
            rows={list}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
      <Panel title="Status de ingestão" subtitle="Último flow e lag por coletor" badge={ingestion.error ? 'Indisponível' : ingList.length} badgeTone={ingestion.error ? 'warning' : 'info'}>
        {ingestion.loading ? <Loading /> : ingestion.error ? <ErrorBox message={ingestion.error} /> : (
          <Table
            columns={[
              { key: 'sensor', label: 'Sensor' },
              { key: 'exporter_ip', label: 'Exporter' },
              { key: 'last_flow_time', label: 'Último flow', render: (r) => fmtTime(r.last_flow_time || r.last_insert_at) },
              { key: 'lag_bytes', label: 'Lag (bytes)', render: (r) => r.lag_bytes ?? '—' },
              { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status || '—'}</Badge> },
            ]}
            rows={ingList}
            keyFor={(r, i) => r.sensor || i}
          />
        )}
      </Panel>
    </div>
  );
}

function Flows() {
  const top = useApi('/api/flows/top?top_type=conversation&limit=30');
  const list = top.data?.items || [];
  return (
    <div className="main-content">
      <Panel title="Top flows (conversas)" subtitle="Agregação real de tráfego" badge={top.error ? 'Indisponível' : list.length} badgeTone={top.error ? 'warning' : 'info'}>
        {top.loading ? <Loading /> : top.error ? <ErrorBox message={top.error} /> : (
          <Table
            columns={[
              { key: 'key', label: 'Conversa' },
              { key: 'bits_s', label: 'Bits/s', render: (r) => fmtBits(r.bits_s) },
              { key: 'packets_s', label: 'Pacotes/s', render: (r) => fmtPps(r.packets_s) },
              { key: 'bytes', label: 'Bytes', render: (r) => Number(r.bytes ?? 0).toLocaleString('pt-BR') },
              { key: 'flows', label: 'Flows' },
              { key: 'percent', label: '%', render: (r) => `${Number(r.percent ?? 0).toFixed(1)}%` },
              { key: 'last_seen', label: 'Último', render: (r) => fmtTime(r.last_seen) },
            ]}
            rows={list}
            keyFor={(r) => r.key}
          />
        )}
      </Panel>
    </div>
  );
}

function Peak() {
  const events = useApi('/api/peak-hunter/events?limit=100');
  const list = events.data?.items || [];
  return (
    <div className="main-content">
      <Panel title="Picos recentes" subtitle="Eventos persistidos pelo Peak Hunter" badge={events.error ? 'Indisponível' : list.length} badgeTone={events.error ? 'warning' : 'info'}>
        {events.loading ? <Loading /> : events.error ? <ErrorBox message={events.error} /> : (
          <Table
            columns={[
              { key: 'id', label: 'ID' },
              { key: 'sensor', label: 'Sensor' },
              { key: 'interface_id', label: 'Interface' },
              { key: 'direction', label: 'Direção' },
              { key: 'metric', label: 'Métrica' },
              { key: 'peak_value', label: 'Pico' },
              { key: 'peak_time', label: 'Horário', render: (r) => fmtTime(r.peak_time) },
            ]}
            rows={list}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
    </div>
  );
}

function App() {
  const [authed, setAuthed] = useState(Boolean(token()));
  const [user, setUser] = useState(null);
  const [page, setPage] = useState('dashboard');
  /** Entidade alvo de um cross-link (anomalia, execução, announcement, conector). */
  const [focus, setFocus] = useState(null);
  const [bootstrapping, setBootstrapping] = useState(Boolean(token()));

  useEffect(() => {
    const onExpired = () => setAuthed(false);
    window.addEventListener('gmjflow-auth-expired', onExpired);
    return () => window.removeEventListener('gmjflow-auth-expired', onExpired);
  }, []);

  useEffect(() => {
    if (!authed) return;
    setBootstrapping(true);
    api('/api/auth/me')
      .then((data) => setUser(data?.user || null))
      .catch(() => setAuthed(false))
      .finally(() => setBootstrapping(false));
  }, [authed]);

  const logout = () => {
    setToken('');
    setUser(null);
    setAuthed(false);
    setPage('dashboard');
  };

  if (!authed) return <Login onSuccess={(u) => { setUser(u); setAuthed(true); }} />;
  if (bootstrapping) return <div className="login-screen"><div className="subtle">Carregando sessão…</div></div>;

  /**
   * Navegação entre páginas do BLOCO 1. `focus` leva a entidade que o operador
   * clicou (anomalia/execução/announcement/conector) para a página de destino
   * abrir o drawer correspondente — sem inventar rota nem endpoint novo.
   */
  const navigate = (nextPage, nextFocus = null) => {
    setFocus(nextFocus);
    setPage(nextPage);
  };
  const goToPage = (nextPage) => {
    setFocus(null);
    setPage(nextPage);
  };
  const pages = {
    dashboard: <Dashboard />,
    anomalies: <Anomalias focus={focus} onNavigate={navigate} />,
    mitigation: <Mitigation focus={focus} onNavigate={navigate} />,
    bgp: <Bgp focus={focus} onNavigate={navigate} />,
    sensors: <SensorsPage onNavigate={navigate} />,
    interfaces: <InterfacesPage onNavigate={navigate} />,
    flows: <FlowsPage focus={focus} onNavigate={navigate} />,
    threat: <Threat />,
    peak: <PeakHunter />,
    vectors: <VectorsPage />,
    alerts: <Alerts onNavigate={navigate} />,
    media: <MediaPage />,
    codecs: <CodecsPage />,
    gmaps: <GlobalMapPage />,
    zones: <ZonesPage onNavigate={navigate} />,
    prefixes: <PrefixesPage onNavigate={navigate} />,
    cgnat: <CgnatPage />,
    database: <DatabasePage />,
    system: <SystemPage />,
    users: <UsersPage user={user} />,
  };
  // Guard: sem `users.view` a rota não é acessível (mesmo por estado interno).
  const activePage = page === 'users' && !hasPermission(user, 'users.view') ? 'dashboard' : page;
  return (
    <div className="app-shell">
      <Sidebar page={activePage} setPage={goToPage} user={user} />
      <main className="main">
        <Header page={activePage} onLogout={logout} />
        {pages[activePage] || pages.dashboard}
      </main>
    </div>
  );
}

class PreviewErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('Erro ao renderizar a Preview V2:', error, info?.componentStack || '');
  }

  render() {
    if (this.state.error) {
      return (
        <div className="login-screen">
          <div className="login-card">
            <div className="preview-env-banner"><i className="status-dot critical pulse" /> {ENV_LABEL}</div>
            <h1>Erro ao renderizar a Preview V2</h1>
            <p className="subtle">Consulte o console ou recarregue a página.</p>
            <pre className="error-detail">{String(this.state.error?.message || this.state.error)}</pre>
            <button className="primary" type="button" onClick={() => window.location.reload()}>Recarregar</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')).render(
  <PreviewErrorBoundary>
    <App />
  </PreviewErrorBoundary>,
);
