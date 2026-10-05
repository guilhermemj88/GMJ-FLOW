import React, { useState } from 'react';
import {
  Badge, ErrorBox, Loading, Panel, Table, api, useApi,
  fmtNumber, fmtTime, severityTone, statusTone,
} from './shared.jsx';

const READ_ONLY = 'Somente leitura';

const IOC_TIERS = [
  ['', 'Todas'],
  ['1', 'P1 — C2'],
  ['2', 'P2 — Botnet/DDoS'],
  ['3', 'P3 — Malware/Comprometido'],
  ['4', 'P4 — Abuso'],
  ['5', 'P5 — Baixo sinal'],
];

const IOC_CATEGORIES = ['', 'c2', 'ddos', 'botnet', 'malware', 'compromised', 'scanner', 'brute_force', 'abuse', 'reputation_malicious', 'unknown'];
const IOC_FRESHNESS = [['', 'Todas'], ['excellent', '≤1h'], ['good', '≤24h'], ['acceptable', '≤7d']];

const SEC_PERIODS = [['15m', '15 min'], ['30m', '30 min'], ['1h', '1 h'], ['6h', '6 h'], ['24h', '24 h'], ['7d', '7 d']];
const SEC_VERDICTS = [['', 'Todos'], ['CONFIRMED_ATTACK', 'Confirmado'], ['LIKELY_ATTACK', 'Provável'], ['WARNING', 'Alerta'], ['INFO', 'Informativo']];
const SEC_TYPES = [['', 'Todos'], ['SYN_FLOOD', 'SYN flood'], ['UDP_FLOOD', 'UDP flood'], ['DNS_AMPLIFICATION', 'DNS amplification'], ['PORT_SCAN_VERTICAL', 'Port scan'], ['NETWORK_SWEEP', 'Network sweep'], ['LOW_SLOW_SCAN', 'Low & slow scan'], ['CARPET_BOMBING', 'Carpet bombing'], ['BRUTE_FORCE', 'Brute force']];
const SEC_DIRECTIONS = [['all', 'Todas'], ['inbound', 'Inbound'], ['outbound', 'Outbound'], ['internal', 'Internal']];
const SEC_CONTEXTS = [['all', 'Todos'], ['external', 'External'], ['customer', 'Customer'], ['cgnat', 'CGNAT'], ['infrastructure', 'Infrastructure']];
const SEC_SCOPES = [['all', 'Todos'], ['single', 'IP único'], ['prefix', 'Prefixo'], ['multi', 'Multi-destino']];
const SEC_STATUSES = [['', 'Todos'], ['active', 'Ativo'], ['investigating', 'Investigando'], ['confirmed', 'Confirmado'], ['benign', 'Benigno'], ['mitigated', 'Mitigado']];
const SEC_CAMPAIGNS = [['all', 'Todos'], ['with', 'Com campanha'], ['without', 'Sem campanha']];
const SEC_AI = [['all', 'Todos'], ['analyzed', 'Analisados'], ['not_analyzed', 'Não analisados'], ['campaign', 'Com campanha']];
const SEC_GROUP = [['country', 'País'], ['city', 'Cidade'], ['asn', 'ASN'], ['campaign', 'Campanha']];
const INFRA_GROUP = [['country', 'País'], ['asn', 'ASN'], ['organization', 'Organização'], ['ip', 'IP']];
const INFRA_CLASS = [['', 'Todas'], ['malicious', 'Malicious'], ['suspicious', 'Suspicious'], ['c2', 'C2']];
const INFRA_TAGS = [['', 'Todas'], ['botnet', 'Botnet'], ['mirai', 'Mirai'], ['telnet', 'Telnet'], ['ssh', 'SSH brute force'], ['port scan', 'Port scan'], ['iot', 'IoT']];

function qs(params) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== '' && v != null) search.set(k, v); });
  const text = search.toString();
  return text ? `?${text}` : '';
}

function Select({ label, value, onChange, options }) {
  return (
    <label className="th-field">
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map(([val, text]) => <option key={val} value={val}>{text}</option>)}
      </select>
    </label>
  );
}

function Kpi({ label, value, tone = '' }) {
  return <div className={`kpi ${tone}`}><span>{label}</span><b>{value ?? '—'}</b></div>;
}

function ThreatTabs({ tab, setTab }) {
  const tabs = [
    ['overview', 'Overview'],
    ['iocs', 'IOCs'],
    ['providers', 'Providers'],
    ['events', 'Eventos / Campanhas'],
    ['maps', 'Mapas'],
    ['audit', 'Auditoria'],
  ];
  return (
    <div className="ti-tabs">
      {tabs.map(([id, label]) => (
        <button key={id} type="button" className={tab === id ? 'ti-tab active' : 'ti-tab'} onClick={() => setTab(id)}>{label}</button>
      ))}
    </div>
  );
}

function SubTabs({ value, setValue, tabs }) {
  return (
    <div className="ti-subtabs">
      {tabs.map(([id, label]) => (
        <button key={id} type="button" className={value === id ? 'ti-subtab active' : 'ti-subtab'} onClick={() => setValue(id)}>{label}</button>
      ))}
    </div>
  );
}

function Drawer({ title, context, onClose, children }) {
  return (
    <div className="ti-drawer-overlay" onClick={onClose}>
      <aside className="ti-drawer" onClick={(e) => e.stopPropagation()}>
        <header>
          <div><div className="subtle">{context}</div><h2>{title}</h2></div>
          <button type="button" className="control" onClick={onClose} aria-label="Fechar">×</button>
        </header>
        <div className="ti-drawer-body">{children}</div>
      </aside>
    </div>
  );
}

function KvGrid({ entries }) {
  const list = entries.filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!list.length) return null;
  return (
    <div className="kv-grid">
      {list.map(([label, value]) => <div key={label}><span>{label}</span><b>{String(value)}</b></div>)}
    </div>
  );
}

function Section({ title, children }) {
  return <section className="ti-section"><h3>{title}</h3>{children}</section>;
}

function Sparkline({ points, valueKey = 'bps' }) {
  const list = (points || []).filter((p) => Number.isFinite(Number(p[valueKey])));
  if (list.length < 2) return <div className="subtle">Série indisponível.</div>;
  const W = 900, H = 90;
  const values = list.map((p) => Number(p[valueKey]));
  const max = Math.max(1, ...values);
  const n = list.length;
  const x = (i) => (i / (n - 1)) * W;
  const y = (v) => H - (v / max) * (H - 8) - 4;
  return (
    <div className="ti-spark">
      <div className="ti-spark-scale"><span>{max.toLocaleString('pt-BR')}</span><span>0</span></div>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-label="Linha do tempo de tráfego">
        <polyline fill="none" stroke="#22d3ee" strokeWidth="2" points={list.map((p, i) => `${x(i)},${y(Number(p[valueKey]))}`).join(' ')} />
      </svg>
      <div className="ti-spark-legend">{list.length} buckets · {valueKey} · {fmtTime(list[0]?.timestamp)} → {fmtTime(list[n - 1]?.timestamp)}</div>
    </div>
  );
}

/* ------------------------------- Overview ------------------------------- */

function ThreatOverview({ onOpenEvent }) {
  const summary = useApi('/api/security/summary?window=60');
  const providers = useApi('/api/threat-intelligence/providers');
  const events = useApi('/api/security/events?limit=200');
  const campaigns = useApi('/api/threat-engine/campaigns?limit=200');
  const decisions = useApi('/api/threat-engine/policy-decisions?limit=500');
  const engine = useApi('/api/threat-engine/status');

  const s = summary.data || {};
  const p = providers.data?.summary || {};
  const decisionItems = decisions.data?.items || [];
  const allowed = decisionItems.filter((d) => String(d.decision) === 'ALLOW_AUTO').length;
  const byType = Object.entries(s.by_type || {}).sort((a, b) => b[1] - a[1]);
  const engineState = engine.data || {};

  return (
    <div className="ti-body">
      <Panel title="Security Overview" subtitle="Janela de 60 min · threat score em modo shadow" badge={summary.error ? 'Indisponível' : `${s.window_minutes ?? 60} min`} badgeTone={summary.error ? 'warning' : 'info'}>
        {summary.loading ? <Loading /> : summary.error ? <ErrorBox message={summary.error} /> : (
          <>
            <div className="ti-kpis">
              <Kpi label="Analisados" value={fmtNumber(s.analyzed)} />
              <Kpi label="Detecções" value={fmtNumber(s.detections)} tone="s" />
              <Kpi label="Suspeitos" value={fmtNumber(s.suspicious)} tone="w" />
              <Kpi label="Security Events" value={fmtNumber(s.security_events)} />
              <Kpi label="Críticos" value={fmtNumber(s.critical)} tone="c" />
              <Kpi label="Altos" value={fmtNumber(s.high)} tone="w" />
              <Kpi label="Corroborados" value={fmtNumber(s.corroborated)} tone="s" />
              <Kpi label="Elegíveis p/ mitigação" value={fmtNumber(s.eligible_for_mitigation)} />
              <Kpi label="Mitigados" value={fmtNumber(s.mitigated)} tone="s" />
            </div>
            {byType.length ? (
              <div className="ti-chips">
                {byType.map(([type, count]) => <span className="ti-chip" key={type}>{type}: {fmtNumber(count)}</span>)}
              </div>
            ) : null}
          </>
        )}
      </Panel>

      <div className="ti-grid-2">
        <Panel title="Resumo de Threat Intelligence" subtitle="Providers, indicadores e atividade recente" badge={providers.error ? 'Indisponível' : `${p.providers ?? '—'} providers`} badgeTone={providers.error ? 'warning' : 'info'}>
          {providers.loading ? <Loading /> : providers.error ? <ErrorBox message={providers.error} /> : (
            <div className="ti-kpis five">
              <Kpi label="Providers ativos" value={`${fmtNumber(p.online)}/${fmtNumber(p.providers)}`} tone="s" />
              <Kpi label="Indicadores ativos" value={fmtNumber(p.records)} />
              <Kpi label="Vetores recentes" value={events.error ? '—' : fmtNumber(events.data?.total)} />
              <Kpi label="Campanhas recentes" value={campaigns.error ? '—' : fmtNumber((campaigns.data?.items || []).length)} />
              <Kpi label="Autorizações automáticas" value={decisions.error ? '—' : fmtNumber(allowed)} tone="w" />
            </div>
          )}
        </Panel>
        <Panel title="Engine comportamental" subtitle="Estado do runtime (read-only)" badge={engine.error ? 'Indisponível' : String(engineState.mode || '—')} badgeTone={engine.error ? 'warning' : (String(engineState.mode) === 'shadow' ? 'info' : 'success')}>
          {engine.loading ? <Loading /> : engine.error ? <ErrorBox message={engine.error} /> : (
            <KvGrid entries={[
              ['Rodando', engineState.running ? 'sim' : 'não'],
              ['Última execução', fmtTime(engineState.last_run)],
              ['Erro', engineState.last_error || '—'],
              ['Vetores', fmtNumber(engineState.vectors)],
              ['Campanhas', fmtNumber(engineState.campaigns)],
              ['Decisões de política', fmtNumber(engineState.policy_decisions)],
              ['Autorizações automáticas', fmtNumber(engineState.automatic_authorizations)],
              ['Mitigações submetidas', fmtNumber(engineState.mitigations_submitted)],
              ['Candidatos RTBH', fmtNumber(engineState.rtbh_candidates)],
            ]} />
          )}
        </Panel>
      </div>

      <Panel title="Eventos recentes" subtitle="Clique para abrir a investigação" actions={<Badge tone="critical">{READ_ONLY}</Badge>} badge={events.error ? 'Indisponível' : fmtNumber(events.data?.total)} badgeTone={events.error ? 'warning' : 'info'}>
        <EventsTable payload={events} onOpen={onOpenEvent} compact />
      </Panel>
    </div>
  );
}

/* --------------------------------- IOCs --------------------------------- */

function ThreatIocs() {
  const [tier, setTier] = useState('');
  const [category, setCategory] = useState('');
  const [provider, setProvider] = useState('');
  const [freshness, setFreshness] = useState('');
  const [search, setSearch] = useState('');
  const [applied, setApplied] = useState({ tier: '', category: '', provider: '', freshness: '', search: '' });
  const [openIp, setOpenIp] = useState('');
  const providers = useApi('/api/threat-intelligence/providers');
  const list = useApi(`/api/threat-intelligence/iocs${qs({ ...applied, limit: 200 })}`);
  const providerOptions = [['', 'Todos'], ...((providers.data?.items || []).map((p) => [p.provider, p.display_name || p.provider]))];
  const items = list.data?.items || [];

  return (
    <div className="ti-body">
      <Panel
        title="IOCs consolidados"
        subtitle="Origem maliciosa externa · prioridade, categoria, confiança e frescor"
        badge={list.error ? 'Indisponível' : fmtNumber(list.data?.total ?? items.length)}
        badgeTone={list.error ? 'warning' : 'info'}
        filters={
          <div className="ti-filters">
            <Select label="Prioridade" value={tier} onChange={setTier} options={IOC_TIERS} />
            <Select label="Categoria" value={category} onChange={setCategory} options={[['', 'Todas'], ...IOC_CATEGORIES.slice(1).map((c) => [c, c])]} />
            <Select label="Provider" value={provider} onChange={setProvider} options={providerOptions} />
            <Select label="Freshness" value={freshness} onChange={setFreshness} options={IOC_FRESHNESS} />
            <label className="th-field"><span>Buscar IP</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="1.2.3.4" /></label>
            <button type="button" className="control" onClick={() => setApplied({ tier, category, provider, freshness, search })}>Aplicar</button>
          </div>
        }
      >
        {list.loading ? <Loading /> : list.error ? <ErrorBox message={list.error} /> : (
          <Table
            onRowClick={(r) => setOpenIp(r.ip)}
            columns={[
              { key: 'ip', label: 'IP' },
              { key: 'priority', label: 'Prioridade', render: (r) => <Badge tone={Number(r.priority) <= 2 ? 'critical' : Number(r.priority) === 3 ? 'warning' : 'info'}>P{r.priority}</Badge> },
              { key: 'category', label: 'Categoria' },
              { key: 'primary_source', label: 'Fonte principal' },
              { key: 'independent_sources', label: 'Fontes indep.' },
              { key: 'confidence', label: 'Confiança', render: (r) => `${fmtNumber(r.confidence)}%` },
              { key: 'botnet_family', label: 'Família' },
              { key: 'last_seen', label: 'Last seen', render: (r) => fmtTime(r.last_seen) },
              { key: 'freshness', label: 'Freshness' },
              { key: 'evidence_count', label: 'Evidências' },
            ]}
            rows={items}
            keyFor={(r) => r.ip}
            empty="Nenhum IOC consolidado para os filtros atuais."
          />
        )}
      </Panel>
      {openIp ? <IocDrawer ip={openIp} onClose={() => setOpenIp('')} /> : null}
    </div>
  );
}

function IocDrawer({ ip, onClose }) {
  const detail = useApi(`/api/threat-intelligence/iocs/${encodeURIComponent(ip)}`);
  const lookup = useApi(`/api/threat-intelligence/lookup/${encodeURIComponent(ip)}`);
  const summary = detail.data?.summary || {};
  const evidence = detail.data?.evidence || [];
  const lookupItems = Array.isArray(lookup.data) ? lookup.data : (lookup.data?.items || []);
  return (
    <Drawer title={ip} context="IOC consolidado · origem maliciosa" onClose={onClose}>
      {detail.loading ? <Loading /> : detail.error ? <ErrorBox message={detail.error} /> : (
        <>
          <KvGrid entries={[
            ['Encontrado', summary.found ? 'sim' : 'não'],
            ['Prioridade', summary.priority != null ? `P${summary.priority}` : '—'],
            ['Categoria', summary.category],
            ['Fonte principal', summary.primary_source],
            ['Confiança', summary.confidence != null ? `${summary.confidence}%` : '—'],
            ['Fontes independentes', summary.independent_sources],
            ['Evidências', summary.evidence_count],
            ['Freshness', summary.freshness],
            ['Last seen', summary.last_seen ? fmtTime(summary.last_seen) : '—'],
          ]} />
          {(summary.bogon || []).length ? (
            <Section title="Bogon / faixa especial">
              <div className="ti-chips">{(summary.bogon || []).map((b, i) => <span className="ti-chip" key={i}>{b.kind} · {b.prefix}</span>)}</div>
            </Section>
          ) : null}
          <Section title="Evidências por provider">
            <Table
              columns={[
                { key: 'provider', label: 'Provider' },
                { key: 'primary_source', label: 'Fonte' },
                { key: 'classification', label: 'Classificação' },
                { key: 'category', label: 'Categoria' },
                { key: 'tier', label: 'Prior.', render: (r) => (r.tier != null ? `P${r.tier}` : '—') },
                { key: 'confidence', label: 'Conf.', render: (r) => (r.confidence != null ? `${r.confidence}%` : '—') },
                { key: 'malware', label: 'Família' },
                { key: 'ports', label: 'Portas', render: (r) => (Array.isArray(r.ports) && r.ports.length ? r.ports.join(', ') : '—') },
                { key: 'last_seen', label: 'Last seen', render: (r) => fmtTime(r.last_seen || r.updated_at) },
                { key: 'tags', label: 'Tags', render: (r) => (Array.isArray(r.tags) && r.tags.length ? r.tags.map((t) => (typeof t === 'string' ? t : t?.name || t?.slug || '')).filter(Boolean).join(', ') : '—') },
              ]}
              rows={evidence}
              keyFor={(r, i) => `${r.provider}-${i}`}
              empty="Sem evidências ativas para este IP."
            />
          </Section>
          <Section title="Lookup por provider (indicadores brutos)">
            {lookup.loading ? <Loading /> : lookup.error ? <ErrorBox message={lookup.error} /> : lookupItems.length === 0 ? <div className="subtle">Sem registro nos providers para este IP.</div> : (
              <Table
                columns={[
                  { key: 'provider', label: 'Provider' },
                  { key: 'classification', label: 'Classificação' },
                  { key: 'asn', label: 'ASN' },
                  { key: 'organization', label: 'Organização' },
                  { key: 'last_seen', label: 'Last seen', render: (r) => fmtTime(r.last_seen) },
                ]}
                rows={lookupItems}
                keyFor={(r, i) => `${r.provider}-${i}`}
              />
            )}
          </Section>
        </>
      )}
    </Drawer>
  );
}

/* ------------------------------- Providers ------------------------------ */

function ThreatProviders() {
  const providers = useApi('/api/threat-intelligence/providers');
  const [openProvider, setOpenProvider] = useState('');
  const items = providers.data?.items || [];
  return (
    <div className="ti-body">
      <Panel
        title="Providers de Threat Intelligence"
        subtitle="Estado configurado; credenciais nunca são exibidas"
        badge={providers.error ? 'Indisponível' : `${fmtNumber(providers.data?.summary?.online)}/${fmtNumber(providers.data?.summary?.providers)} ativos`}
        badgeTone={providers.error ? 'warning' : 'info'}
        actions={<Badge tone="critical">{READ_ONLY}</Badge>}
      >
        {providers.loading ? <Loading /> : providers.error ? <ErrorBox message={providers.error} /> : (
          <div className="ti-provider-grid">
            {items.map((p) => (
              <button type="button" className="ti-provider-card" key={p.provider} onClick={() => setOpenProvider(p.provider)}>
                <div className="ti-provider-top">
                  <b>{p.display_name || p.provider}</b>
                  <Badge tone={p.status === 'ACTIVE' ? 'success' : p.status === 'DISABLED' ? 'info' : p.status === 'DEGRADED' ? 'warning' : 'critical'}>{p.status}</Badge>
                </div>
                <div className="ti-provider-meta">
                  <span>Indicadores: <b>{fmtNumber(p.item_count)}</b></span>
                  <span>Credencial: <b>{p.credential_configured ? 'configurada' : 'ausente'}</b></span>
                  <span>Habilitado: <b>{p.enabled ? 'sim' : 'não'}</b></span>
                  <span>Último sync: <b>{fmtTime(p.last_sync)}</b></span>
                </div>
                {p.last_error ? <div className="ti-provider-error">{p.last_error}</div> : null}
              </button>
            ))}
          </div>
        )}
      </Panel>
      {openProvider ? <ProviderDrawer provider={openProvider} onClose={() => setOpenProvider('')} /> : null}
    </div>
  );
}

function ProviderDrawer({ provider, onClose }) {
  const detail = useApi(`/api/threat-intelligence/providers/${encodeURIComponent(provider)}`);
  const d = detail.data || {};
  return (
    <Drawer title={d.display_name || provider} context="Provider de Threat Intelligence" onClose={onClose}>
      <div className="ti-readonly-note"><Badge tone="critical">{READ_ONLY}</Badge><span>Sync e teste de provider não são executados pela preview.</span></div>
      {detail.loading ? <Loading /> : detail.error ? <ErrorBox message={detail.error} /> : (
        <>
          <KvGrid entries={[
            ['Provider', d.provider],
            ['Estado', d.status],
            ['Habilitado', d.enabled ? 'sim' : 'não'],
            ['Credencial configurada', d.credential_configured ? 'sim' : 'não'],
            ['Indicadores usáveis', fmtNumber(d.item_count)],
            ['Dados utilizáveis', d.data_usable ? 'sim' : 'não'],
            ['Intervalo de sync', d.sync_interval_seconds != null ? `${fmtNumber(d.sync_interval_seconds)} s` : '—'],
            ['Último sync', fmtTime(d.last_sync)],
            ['Duração do sync', d.last_sync_duration_ms != null ? `${fmtNumber(d.last_sync_duration_ms)} ms` : '—'],
            ['Último sucesso', fmtTime(d.last_success)],
            ['Próximo sync', fmtTime(d.next_sync)],
            ['Atualizado', fmtTime(d.updated_at)],
          ]} />
          {d.last_error ? <Section title="Último erro"><div className="ti-provider-error">{d.last_error}</div></Section> : null}
          {d.config && Object.keys(d.config).length ? (
            <Section title="Configuração"><KvGrid entries={Object.entries(d.config).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)])} /></Section>
          ) : null}
          <div className="ti-actions-disabled">
            <button type="button" className="control" disabled>Testar provider</button>
            <button type="button" className="control" disabled>Sincronizar</button>
            <span className="subtle">{READ_ONLY}</span>
          </div>
        </>
      )}
    </Drawer>
  );
}

/* --------------------------- Events / Campaigns ------------------------- */

function EventsTable({ payload, onOpen, compact = false }) {
  const items = payload.data?.items || [];
  if (payload.loading) return <Loading />;
  if (payload.error) return <ErrorBox message={payload.error} />;
  return (
    <Table
      onRowClick={onOpen}
      columns={[
        { key: 'attack_type', label: 'Tipo / família', render: (r) => <><b>{r.attack_type}</b><span className="subtle"> {r.attack_family}</span><br /><code>{r.event_id}</code></> },
        { key: 'src_ip', label: 'Origem → alvo', render: (r) => `${r.src_ip || 'distribuída'} → ${r.target_ip || r.target_prefix || '—'}` },
        { key: 'detector', label: 'Detector', render: (r) => <>{r.detector}<br /><span className="subtle">{r.verdict} · conf. {fmtNumber(Number(r.confidence || 0) <= 1 ? Number(r.confidence || 0) * 100 : Number(r.confidence || 0), 0)}%</span></> },
        { key: 'severity', label: 'Sev.', render: (r) => <Badge tone={severityTone(r.severity)}>{r.severity}</Badge> },
        { key: 'sensor', label: 'Sensor' },
        { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
        ...(compact ? [] : [{ key: 'last_seen', label: 'Última', render: (r) => fmtTime(r.last_seen) }]),
      ]}
      rows={items}
      keyFor={(r, i) => r.event_id || r.id || i}
      empty="Nenhum evento de segurança."
    />
  );
}

function CampaignsTable({ payload }) {
  const items = payload.data?.items || [];
  if (payload.loading) return <Loading />;
  if (payload.error) return <ErrorBox message={payload.error} />;
  return (
    <Table
      columns={[
        { key: 'campaign_id', label: 'Campanha', render: (r) => <><code>{r.campaign_id}</code><br /><span className="subtle">{fmtTime(r.last_seen)}</span></> },
        { key: 'classification', label: 'Classe / alvo', render: (r) => <><b>{r.classification}</b><br />{r.target_prefix || '—'}</> },
        { key: 'coordination_score', label: 'Coordenação', render: (r) => `${fmtNumber(r.coordination_score)} · ${Number(r.packets_per_second || 0).toFixed(1)} pps` },
        { key: 'unique_sources', label: 'Fontes / ASNs', render: (r) => `${fmtNumber(r.unique_sources)} / ${fmtNumber(r.unique_source_asns)}` },
        { key: 'campaign_risk_score', label: 'Risco', render: (r) => `${fmtNumber(r.campaign_risk_score)}${r.campaign_risk_band ? ` · ${r.campaign_risk_band}` : ''}` },
        { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
      ]}
      rows={items}
      keyFor={(r) => r.campaign_id}
      empty="Nenhuma campanha recente."
    />
  );
}

function flowspecText(proposal) {
  if (!proposal || !proposal.action) return '—';
  const match = [
    proposal.src_prefix && `src ${proposal.src_prefix}`,
    proposal.dst_prefix && `dst ${proposal.dst_prefix}`,
    proposal.protocol,
    proposal.src_port && `sport ${proposal.src_port}`,
    proposal.dst_port && `dport ${proposal.dst_port}`,
    proposal.tcp_flags && `flags ${proposal.tcp_flags}`,
  ].filter(Boolean).join(' · ');
  return `${proposal.action}: ${match}`;
}

function DecisionsTable({ payload }) {
  const items = payload.data?.items || [];
  if (payload.loading) return <Loading />;
  if (payload.error) return <ErrorBox message={payload.error} />;
  return (
    <Table
      columns={[
        { key: 'decision', label: 'Decisão', render: (r) => <Badge tone={r.decision === 'ALLOW_AUTO' ? 'success' : 'info'}>{r.decision}</Badge> },
        { key: 'classification', label: 'Classificação' },
        { key: 'policy_score', label: 'Policy / Groq', render: (r) => `${fmtNumber(r.policy_score)} · ${(Number(r.confidence || 0) * 100).toFixed(1)}%` },
        { key: 'decision_source', label: 'Origem', render: (r) => <>{r.decision_source}{(r.intel_sources || []).length ? <><br /><span className="subtle">{(r.intel_sources || []).slice(0, 3).join(', ')}</span></> : null}</> },
        { key: 'proposal', label: 'FlowSpec proposto', render: (r) => <code className="th-flowspec">{flowspecText(r.proposal)}</code> },
        { key: 'ttl_seconds', label: 'TTL', render: (r) => (r.ttl_seconds ? `${fmtNumber(r.ttl_seconds)} s` : '—') },
        { key: 'reason', label: 'Motivo', render: (r) => r.reason || r.non_mitigation_reason || '—' },
        { key: 'created_at', label: 'Data', render: (r) => fmtTime(r.created_at) },
      ]}
      rows={items}
      keyFor={(r) => r.id}
      empty="Nenhuma decisão registrada."
    />
  );
}

function ThreatEvents({ onOpenEvent }) {
  const [sub, setSub] = useState('events');
  const events = useApi('/api/security/events?limit=200');
  const campaigns = useApi('/api/threat-engine/campaigns?limit=200');
  const decisions = useApi('/api/threat-engine/policy-decisions?limit=200');

  return (
    <div className="ti-body">
      <SubTabs value={sub} setValue={setSub} tabs={[['events', 'Eventos (attack vectors)'], ['campaigns', 'Campanhas'], ['decisions', 'Decisões / FlowSpec']]} />
      {sub === 'events' ? (
        <Panel title="Attack Vectors / Security Events" subtitle="Clique para abrir a investigação do evento" badge={events.error ? 'Indisponível' : fmtNumber(events.data?.total)} badgeTone={events.error ? 'warning' : 'info'}>
          <EventsTable payload={events} onOpen={(r) => onOpenEvent(r.event_id || r.id)} />
        </Panel>
      ) : null}
      {sub === 'campaigns' ? (
        <Panel title="Campaign Vectors" subtitle="Coordenação, fontes e risco por campanha" badge={campaigns.error ? 'Indisponível' : (campaigns.data?.items || []).length} badgeTone={campaigns.error ? 'warning' : 'info'}>
          <CampaignsTable payload={campaigns} />
        </Panel>
      ) : null}
      {sub === 'decisions' ? (
        <Panel title="Decisões, FlowSpec e TTL" subtitle="Policy determinística + Groq (não executa mitigação)" badge={decisions.error ? 'Indisponível' : (decisions.data?.items || []).length} badgeTone={decisions.error ? 'warning' : 'info'}>
          <DecisionsTable payload={decisions} />
        </Panel>
      ) : null}
    </div>
  );
}

function SecurityEventDrawer({ eventRef, onClose }) {
  const event = useApi(`/api/security/events/${encodeURIComponent(eventRef)}`);
  const evidence = useApi(`/api/security/events/${encodeURIComponent(eventRef)}/evidence?sample_limit=100`);
  const sources = useApi(`/api/security/events/${encodeURIComponent(eventRef)}/sources?limit=50`);
  const related = useApi(`/api/security/events/${encodeURIComponent(eventRef)}/related?limit=20`);
  const intel = useApi(`/api/security/events/${encodeURIComponent(eventRef)}/threat-intel`);
  const ai = useApi(`/api/security/events/${encodeURIComponent(eventRef)}/ai-analysis`);
  const traffic = useApi(`/api/security/events/${encodeURIComponent(eventRef)}/traffic?padding_seconds=600`);
  const e = event.data || {};
  const score = e.threat_score || {};

  return (
    <Drawer title={e.attack_type || 'Evento de segurança'} context={e.event_id ? `Security Event · ${e.event_id}` : 'Security Event'} onClose={onClose}>
      <div className="ti-readonly-note"><Badge tone="critical">{READ_ONLY}</Badge><span>Marcar benigno/confirmado e reanálise de IA não são executados pela preview.</span></div>
      {event.loading ? <Loading /> : event.error ? <ErrorBox message={event.error} /> : (
        <>
          <KvGrid entries={[
            ['Origem (maliciosa)', e.src_ip],
            ['Alvo / vítima', e.target_ip || e.target_prefix],
            ['Prefixo origem', e.src_prefix],
            ['Direção', e.direction],
            ['Roles', `${e.src_role || '—'} → ${e.dst_role || '—'}`],
            ['Protocolo', e.protocol],
            ['Severidade', e.severity],
            ['Veredito', e.verdict],
            ['Score detector', fmtNumber(e.detector_score)],
            ['Confiança', `${(Number(e.confidence || 0) * 100).toFixed(1)}%`],
            ['Threat score', score.score != null ? `${fmtNumber(score.score)} · ${score.band || ''}` : '—'],
            ['Recorrência', fmtNumber(e.recurrence_count)],
            ['Sensor', e.sensor],
            ['Exporter', e.exporter],
            ['PPS', fmtNumber(e.packets_per_second, 1)],
            ['Bits/s', fmtNumber(e.bits_per_second, 1)],
            ['Flows/s', fmtNumber(e.flows_per_second, 1)],
            ['Fontes únicas', fmtNumber(e.unique_sources)],
            ['Destinos únicos', fmtNumber(e.unique_destinations)],
            ['Duração', e.duration_seconds != null ? `${fmtNumber(e.duration_seconds, 1)} s` : '—'],
            ['Primeira', fmtTime(e.first_seen)],
            ['Última', fmtTime(e.last_seen)],
            ['Status', e.status],
            ['IA', e.ai_analysis_status],
          ]} />

          {e.detection_reason ? <Section title="Motivo da detecção"><div className="subtle">{e.detection_reason}</div></Section> : null}
          {e.network_context && Object.keys(e.network_context).length ? (
            <Section title="Contexto de rede"><KvGrid entries={Object.entries(e.network_context).map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v) : String(v)])} /></Section>
          ) : null}

          <Section title="Linha do tempo (tráfego)">
            {traffic.loading ? <Loading /> : traffic.error ? <ErrorBox message={traffic.error} /> : (
              <Sparkline points={traffic.data?.points || []} valueKey="bps" />
            )}
          </Section>

          <Section title="Evidências (agregado)">
            {evidence.loading ? <Loading /> : evidence.error ? <ErrorBox message={evidence.error} /> : (
              <>
                <div className="subtle">Fonte: {evidence.data?.source || '—'} · agregado {evidence.data?.aggregate_available ? 'disponível' : 'indisponível'}</div>
                <KvGrid entries={[
                  ['Amostras', (evidence.data?.sample_conversations || []).length],
                  ['Protocolos', (evidence.data?.protocols || []).map((p) => p.protocol).filter(Boolean).join(', ')],
                ]} />
                {(evidence.data?.sample_conversations || []).length ? (
                  <Table
                    columns={[
                      { key: 'source_ip', label: 'Origem' },
                      { key: 'destination_ip', label: 'Destino' },
                      { key: 'protocol', label: 'Proto' },
                      { key: 'packets', label: 'Pacotes', render: (r) => fmtNumber(r.packets) },
                      { key: 'bytes', label: 'Bytes', render: (r) => fmtNumber(r.bytes) },
                      { key: 'last_seen', label: 'Última', render: (r) => fmtTime(r.last_seen) },
                    ]}
                    rows={(evidence.data?.sample_conversations || []).slice(0, 25)}
                    keyFor={(r, i) => `${r.source_ip}-${r.destination_ip}-${i}`}
                  />
                ) : null}
              </>
            )}
          </Section>

          <Section title="Fontes (origens maliciosas)">
            {sources.loading ? <Loading /> : sources.error ? <ErrorBox message={sources.error} /> : (
              <Table
                columns={[
                  { key: 'source_ip', label: 'IP origem' },
                  { key: 'source_asn', label: 'ASN' },
                  { key: 'pps', label: 'pps', render: (r) => fmtNumber(r.pps, 2) },
                  { key: 'packets', label: 'Pacotes', render: (r) => fmtNumber(r.packets) },
                  { key: 'bytes', label: 'Bytes', render: (r) => fmtNumber(r.bytes) },
                ]}
                rows={(sources.data?.items || []).slice(0, 25)}
                keyFor={(r, i) => `${r.source_ip}-${i}`}
                empty="Sem fontes disponíveis."
              />
            )}
          </Section>

          <Section title="Threat Intelligence relacionada">
            {intel.loading ? <Loading /> : intel.error ? <ErrorBox message={intel.error} /> : (
              <>
                <div className="subtle">{intel.data?.interpretation || ''}</div>
                <div className="ti-chips">
                  {Object.entries(intel.data?.threat_intel?.source_intel || {}).slice(0, 12).map(([k, v]) => (
                    <span className="ti-chip" key={k}>{k}: {typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                  ))}
                </div>
              </>
            )}
          </Section>

          <Section title="Eventos relacionados">
            {related.loading ? <Loading /> : related.error ? <ErrorBox message={related.error} /> : (
              <Table
                columns={[
                  { key: 'event_id', label: 'Evento' },
                  { key: 'attack_type', label: 'Tipo' },
                  { key: 'src_ip', label: 'Origem' },
                  { key: 'target_ip', label: 'Alvo' },
                  { key: 'last_seen', label: 'Última', render: (r) => fmtTime(r.last_seen) },
                ]}
                rows={(related.data?.items || []).slice(0, 20)}
                keyFor={(r, i) => r.event_id || i}
                empty="Sem eventos relacionados."
              />
            )}
          </Section>

          <Section title="Análise IA">
            {ai.loading ? <Loading /> : ai.error ? <div className="subtle">Não analisado por IA ({ai.error}).</div> : (
              <KvGrid entries={[
                ['Status', ai.data?.status],
                ['Provider', ai.data?.provider],
                ['Modelo', ai.data?.model],
                ['Veredito', ai.data?.analysis?.verdict || ai.data?.verdict],
                ['Confiança', ai.data?.analysis?.confidence != null ? `${ai.data.analysis.confidence}%` : (ai.data?.confidence != null ? `${ai.data.confidence}%` : '—')],
                ['Analisado em', fmtTime(ai.data?.analyzed_at || ai.data?.created_at)],
              ]} />
            )}
          </Section>
        </>
      )}
    </Drawer>
  );
}

/* --------------------------------- Maps --------------------------------- */

function GeoScatter({ points }) {
  const list = (points || []).filter((p) => Number.isFinite(Number(p.lat)) && Number.isFinite(Number(p.lon)));
  if (!list.length) return <div className="subtle" style={{ padding: '14px 16px' }}>Sem pontos geolocalizados para os filtros atuais.</div>;
  const lats = list.map((p) => Number(p.lat));
  const lons = list.map((p) => Number(p.lon));
  const minLat = Math.min(...lats), maxLat = Math.max(...lats);
  const minLon = Math.min(...lons), maxLon = Math.max(...lons);
  const padLat = Math.max(3, (maxLat - minLat) * 0.15);
  const padLon = Math.max(3, (maxLon - minLon) * 0.15);
  const loLat = minLat - padLat, hiLat = maxLat + padLat;
  const loLon = minLon - padLon, hiLon = maxLon + padLon;
  const spanLat = (hiLat - loLat) || 1;
  const spanLon = (hiLon - loLon) || 1;
  const maxCount = Math.max(1, ...list.map((p) => Number(p.event_count) || 1));
  return (
    <div className="ti-scatter">
      <div className="ti-scatter-grid" />
      {list.map((p, i) => {
        const x = ((Number(p.lon) - loLon) / spanLon) * 100;
        const y = 100 - ((Number(p.lat) - loLat) / spanLat) * 100;
        const size = 8 + (Number(p.event_count) || 1) / maxCount * 16;
        return (
          <span
            key={p.key || i}
            className="ti-scatter-dot"
            style={{ left: `${x}%`, top: `${y}%`, width: size, height: size, background: p.color || '#38bdf8' }}
            title={`${p.label} · ${p.event_count} evento(s) · ${p.tier}`}
          />
        );
      })}
      <div className="ti-scatter-legend">● crítico ● alto ● alerta ● informativo · projeção lat/lon dos eventos reais (sem base mock)</div>
    </div>
  );
}

function ThreatMaps() {
  const [sub, setSub] = useState('security');
  return (
    <div className="ti-body">
      <SubTabs value={sub} setValue={setSub} tabs={[['security', 'Situação de segurança'], ['infra', 'Infraestrutura hostil']]} />
      {sub === 'security' ? <SecurityMapPanel /> : <InfraMapPanel />}
    </div>
  );
}

function SecurityMapPanel() {
  const [period, setPeriod] = useState('24h');
  const [severity, setSeverity] = useState('');
  const [verdict, setVerdict] = useState('');
  const [attackType, setAttackType] = useState('');
  const [direction, setDirection] = useState('all');
  const [context, setContext] = useState('all');
  const [scope, setScope] = useState('all');
  const [status, setStatus] = useState('');
  const [campaign, setCampaign] = useState('all');
  const [aiStatus, setAiStatus] = useState('all');
  const [groupBy, setGroupBy] = useState('country');
  const [applied, setApplied] = useState(null);

  const params = applied || { period, severity, verdict, attack_type: attackType, direction, context, target_scope: scope, status, campaign, ai_status: aiStatus, group_by: groupBy, limit: 400 };
  const data = useApi(`/api/threat-intelligence/security-map${qs(params)}`);
  const points = data.data?.points || [];
  const ranking = data.data?.ranking || [];
  const summary = data.data?.summary || {};

  const presets = {
    recent: { period: '1h', severity: '', verdict: '', attack_type: '', direction: 'all', context: 'all', target_scope: 'all', status: '', campaign: 'all', ai_status: 'all', group_by: groupBy, limit: 400 },
    critical: { period: '24h', severity: 'CRITICAL', verdict: '', attack_type: '', direction: 'all', context: 'all', target_scope: 'all', status: '', campaign: 'all', ai_status: 'all', group_by: groupBy, limit: 400 },
    confirmed: { period: '7d', severity: '', verdict: 'CONFIRMED_ATTACK', attack_type: '', direction: 'all', context: 'all', target_scope: 'all', status: '', campaign: 'all', ai_status: 'all', group_by: groupBy, limit: 400 },
    analyzing: { period: '24h', severity: '', verdict: '', attack_type: '', direction: 'all', context: 'all', target_scope: 'all', status: 'investigating', campaign: 'all', ai_status: 'all', group_by: groupBy, limit: 400 },
  };

  return (
    <div className="ti-body">
      <Panel
        title="Mapa de situação de segurança"
        subtitle="Origem (inbound) e destino externo (outbound) · determinístico"
        badge={data.error ? 'Indisponível' : `${fmtNumber(summary.total_events)} eventos · ${fmtNumber(summary.located_events)} no mapa`}
        badgeTone={data.error ? 'warning' : 'info'}
        filters={
          <div className="ti-filters">
            <Select label="Período" value={period} onChange={(v) => { setPeriod(v); setApplied(null); }} options={SEC_PERIODS} />
            <Select label="Severidade" value={severity} onChange={(v) => { setSeverity(v); setApplied(null); }} options={[['', 'Todas'], ['CRITICAL', 'Crítica'], ['HIGH', 'Alta'], ['MEDIUM', 'Média'], ['LOW', 'Baixa'], ['INFO', 'Informativa']]} />
            <Select label="Veredito" value={verdict} onChange={(v) => { setVerdict(v); setApplied(null); }} options={SEC_VERDICTS} />
            <Select label="Tipo" value={attackType} onChange={(v) => { setAttackType(v); setApplied(null); }} options={SEC_TYPES} />
            <Select label="Direção" value={direction} onChange={(v) => { setDirection(v); setApplied(null); }} options={SEC_DIRECTIONS} />
            <Select label="Contexto" value={context} onChange={(v) => { setContext(v); setApplied(null); }} options={SEC_CONTEXTS} />
            <Select label="Alvo" value={scope} onChange={(v) => { setScope(v); setApplied(null); }} options={SEC_SCOPES} />
            <Select label="Status" value={status} onChange={(v) => { setStatus(v); setApplied(null); }} options={SEC_STATUSES} />
            <Select label="Campanha" value={campaign} onChange={(v) => { setCampaign(v); setApplied(null); }} options={SEC_CAMPAIGNS} />
            <Select label="Análise IA" value={aiStatus} onChange={(v) => { setAiStatus(v); setApplied(null); }} options={SEC_AI} />
            <Select label="Agrupar" value={groupBy} onChange={(v) => { setGroupBy(v); setApplied(null); }} options={SEC_GROUP} />
            <div className="ti-presets">
              <button type="button" className="control" onClick={() => setApplied(presets.recent)}>Mais recentes</button>
              <button type="button" className="control" onClick={() => setApplied(presets.critical)}>Críticos</button>
              <button type="button" className="control" onClick={() => setApplied(presets.confirmed)}>Confirmados</button>
              <button type="button" className="control" onClick={() => setApplied(presets.analyzing)}>Em análise</button>
            </div>
          </div>
        }
      >
        {data.loading ? <Loading /> : data.error ? <ErrorBox message={data.error} /> : (
          <div className="ti-grid-map">
            <GeoScatter points={points} />
            <div className="ti-map-side">
              <KvGrid entries={Object.entries(summary).filter(([, v]) => typeof v !== 'object').slice(0, 12).map(([k, v]) => [k, String(v)])} />
            </div>
          </div>
        )}
      </Panel>
      <Panel title="Ranking por agrupamento" subtitle="Top pontos do mapa de situação" badge={ranking.length} badgeTone="info">
        {data.loading ? <Loading /> : data.error ? <ErrorBox message={data.error} /> : (
          <Table
            columns={[
              { key: 'label', label: 'Agrupamento' },
              { key: 'tier', label: 'Tier', render: (r) => <Badge tone={r.tier === 'critical' ? 'critical' : r.tier === 'high' ? 'warning' : 'info'}>{r.tier}</Badge> },
              { key: 'event_count', label: 'Eventos' },
              { key: 'critical_count', label: 'Críticos' },
              { key: 'confirmed_count', label: 'Confirmados' },
              { key: 'max_threat_score', label: 'Threat score', render: (r) => fmtNumber(r.max_threat_score) },
            ]}
            rows={ranking}
            keyFor={(r, i) => r.key || i}
            empty="Sem agrupamentos."
          />
        )}
      </Panel>
    </div>
  );
}

function InfraMapPanel() {
  const [groupBy, setGroupBy] = useState('country');
  const [provider, setProvider] = useState('');
  const [classification, setClassification] = useState('');
  const [tag, setTag] = useState('');
  const [applied, setApplied] = useState(null);
  const providers = useApi('/api/threat-intelligence/providers');
  const providerOptions = [['', 'Todos'], ...((providers.data?.items || []).map((p) => [p.provider, p.display_name || p.provider]))];
  const params = applied || { group_by: groupBy, provider, classification, tag, limit: 500 };
  const data = useApi(`/api/threat-intelligence/map${qs(params)}`);
  const items = data.data?.items || [];

  return (
    <Panel
      title="Infraestrutura hostil (indicadores externos)"
      subtitle="Agregado por país, ASN, organização ou IP · origem maliciosa"
      badge={data.error ? 'Indisponível' : fmtNumber(items.length)}
      badgeTone={data.error ? 'warning' : 'info'}
      filters={
        <div className="ti-filters">
          <Select label="Agrupar" value={groupBy} onChange={(v) => { setGroupBy(v); setApplied(null); }} options={INFRA_GROUP} />
          <Select label="Provider" value={provider} onChange={(v) => { setProvider(v); setApplied(null); }} options={providerOptions} />
          <Select label="Classificação" value={classification} onChange={(v) => { setClassification(v); setApplied(null); }} options={INFRA_CLASS} />
          <Select label="Tag" value={tag} onChange={(v) => { setTag(v); setApplied(null); }} options={INFRA_TAGS} />
          <button type="button" className="control" onClick={() => setApplied({ group_by: groupBy, provider, classification, tag, limit: 500 })}>Aplicar</button>
        </div>
      }
    >
      {data.loading ? <Loading /> : data.error ? <ErrorBox message={data.error} /> : (
        <Table
          columns={[
            { key: 'label', label: 'Agrupamento', render: (r) => r.label || r.key },
            { key: 'count', label: 'Indicadores', render: (r) => fmtNumber(r.count) },
            { key: 'unique_ips', label: 'IPs únicos', render: (r) => fmtNumber(r.unique_ips) },
            { key: 'organization', label: 'Organização' },
            { key: 'predominant_classification', label: 'Classificação' },
            { key: 'top_organizations', label: 'Top organizações', render: (r) => (r.top_organizations || []).slice(0, 3).map((o) => `${o.name} (${o.count})`).join(', ') || '—' },
            { key: 'top_tags', label: 'Top tags', render: (r) => (r.top_tags || []).slice(0, 3).map((o) => `${o.name} (${o.count})`).join(', ') || '—' },
            { key: 'providers', label: 'Providers', render: (r) => (r.providers || []).join(', ') || '—' },
          ]}
          rows={items}
          keyFor={(r, i) => r.key || i}
          empty="Sem indicadores para os filtros atuais."
        />
      )}
    </Panel>
  );
}

/* -------------------------------- Auditoria ------------------------------ */

function ThreatAudit() {
  const sync = useApi('/api/threat-intelligence/audit?limit=200');
  const engine = useApi('/api/threat-engine/audit?limit=200');
  const contexts = useApi('/api/threat-intelligence/network-contexts');
  return (
    <div className="ti-body">
      <Panel title="Auditoria de sincronização de providers" subtitle="Histórico de sync (somente leitura)" badge={sync.error ? 'Indisponível' : (sync.data?.items || []).length} badgeTone={sync.error ? 'warning' : 'info'}>
        {sync.loading ? <Loading /> : sync.error ? <ErrorBox message={sync.error} /> : (
          <div className="table-scroll"><table><thead><tr>
            <th>Provider</th><th>Status</th><th>Itens</th><th>Duração</th><th>Erro</th><th>Quando</th>
          </tr></thead><tbody>
            {(sync.data?.items || []).length === 0 ? <tr><td colSpan={6} className="subtle">Sem registros.</td></tr> : (sync.data?.items || []).map((row, i) => (
              <tr key={row.id || i}>
                <td>{row.provider || '—'}</td>
                <td><Badge tone={statusTone(row.status)}>{row.status || '—'}</Badge></td>
                <td>{fmtNumber(row.item_count)}</td>
                <td>{row.duration_ms != null ? `${fmtNumber(row.duration_ms)} ms` : '—'}</td>
                <td>{row.error || row.message || '—'}</td>
                <td>{fmtTime(row.created_at || row.started_at)}</td>
              </tr>
            ))}
          </tbody></table></div>
        )}
      </Panel>
      <Panel title="Auditoria do engine" subtitle="Eventos internos do threat engine" badge={engine.error ? 'Indisponível' : (engine.data?.items || []).length} badgeTone={engine.error ? 'warning' : 'info'}>
        {engine.loading ? <Loading /> : engine.error ? <ErrorBox message={engine.error} /> : (
          <Table
            columns={[
              { key: 'id', label: 'ID' },
              { key: 'event_type', label: 'Evento' },
              { key: 'detector', label: 'Detector' },
              { key: 'reason', label: 'Motivo' },
              { key: 'created_at', label: 'Quando', render: (r) => fmtTime(r.created_at) },
            ]}
            rows={(engine.data?.items || []).slice(0, 100)}
            keyFor={(r, i) => r.id || i}
            empty="Sem registros."
          />
        )}
      </Panel>
      <Panel title="Contextos de rede" subtitle="Roles e hierarquia por sensor/exporter (consulta)" badge={contexts.error ? 'Indisponível' : (contexts.data?.items || []).length} badgeTone={contexts.error ? 'warning' : 'info'}>
        {contexts.loading ? <Loading /> : contexts.error ? <ErrorBox message={contexts.error} /> : (
          <Table
            columns={[
              { key: 'name', label: 'Nome' },
              { key: 'context_type', label: 'Tipo' },
              { key: 'sensor_name', label: 'Sensor' },
              { key: 'exporter_ip', label: 'Exporter' },
              { key: 'input_if', label: 'In if' },
              { key: 'output_if', label: 'Out if' },
              { key: 'protected_ranges', label: 'Faixas protegidas', render: (r) => (r.protected_ranges || []).join(', ') || '—' },
              { key: 'enabled', label: 'Ativo', render: (r) => <Badge tone={r.enabled ? 'success' : 'warning'}>{r.enabled ? 'Sim' : 'Não'}</Badge> },
            ]}
            rows={contexts.data?.items || []}
            keyFor={(r) => r.id}
            empty="Sem contextos de rede."
          />
        )}
      </Panel>
    </div>
  );
}

/* --------------------------------- Root --------------------------------- */

export default function Threat() {
  const [tab, setTab] = useState('overview');
  const [eventRef, setEventRef] = useState('');
  return (
    <div className="main-content">
      <div className="ti-head">
        <ThreatTabs tab={tab} setTab={setTab} />
        <Badge tone="critical" pulse>{READ_ONLY}</Badge>
      </div>
      {tab === 'overview' ? <ThreatOverview onOpenEvent={setEventRef} /> : null}
      {tab === 'iocs' ? <ThreatIocs /> : null}
      {tab === 'providers' ? <ThreatProviders /> : null}
      {tab === 'events' ? <ThreatEvents onOpenEvent={setEventRef} /> : null}
      {tab === 'maps' ? <ThreatMaps /> : null}
      {tab === 'audit' ? <ThreatAudit /> : null}
      {eventRef ? <SecurityEventDrawer eventRef={eventRef} onClose={() => setEventRef('')} /> : null}
    </div>
  );
}
