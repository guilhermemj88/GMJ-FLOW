import React, { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  EmptyState,
  EntityLink,
  ErrorBox,
  Loading,
  Panel,
  ReadOnlyAction,
  StatusDot,
  Table,
  fmtNumber,
  fmtTime,
  stateTone,
  useApi,
} from './shared.jsx';

/**
 * BLOCO 1.5 — Alertas (PREVIEW V2, somente leitura).
 *
 * Central operacional agregadora: NÃO duplica a lógica dos módulos de origem e
 * não recria drawers. Cada fonte é um feed independente — se uma falhar, as
 * demais continuam visíveis e o erro aparece só no feed afetado (nunca
 * convertido em zero).
 *
 * Fontes reais (confirmadas no :8080 e no backend):
 * 1. /api/anomalies/active?limit=1000        → todas as anomalias ativas
 * 2. /api/bgp/announcements?limit=500        → status ∈ {pending_approval, failed, failed_withdraw, peer_down}
 * 3. /api/mitigation/executions?limit=500    → status ∈ {failed, blocked}
 * 4. /api/collectors/health                  → status ∈ {atrasado, sem_flow_recente}
 */

const BGP_ATTENTION = ['pending_approval', 'failed', 'failed_withdraw', 'peer_down'];
const MITIGATION_ATTENTION = ['failed', 'blocked'];
const COLLECTOR_ATTENTION = ['atrasado', 'sem_flow_recente'];

const SOURCES = [
  { value: 'anomaly', label: 'Anomalia' },
  { value: 'mitigation', label: 'Mitigação' },
  { value: 'bgp', label: 'BGP / Announcement' },
  { value: 'collector', label: 'Coletor' },
];

const SEVERITIES = [
  { value: 'critical', label: 'Critical' },
  { value: 'warning', label: 'Warning' },
  { value: 'info', label: 'Info' },
];

const SEVERITY_RANK = { critical: 0, warning: 1, info: 2 };

/** Ações de escrita: existem na produção e estão bloqueadas no preview. */
const READ_ONLY_ACTIONS = [
  ['Reconhecer (ack)', 'POST /api/anomalies/{id}/ack — default-deny no preview', 'C'],
  ['Fechar (close)', 'POST /api/anomalies/{id}/close — default-deny no preview', 'C'],
  ['Mitigar', 'POST /api/anomalies/{id}/mitigation/apply — default-deny no preview', 'C'],
  ['Aprovar anúncio', 'POST /api/bgp/announcements/{id}/approve — default-deny no preview', 'C'],
  ['Retirar anúncio', 'POST /api/bgp/announcements/{id}/withdraw — default-deny no preview', 'C'],
  ['Recover session', 'POST /api/bgp/connectors/recover-sessions — default-deny no preview', 'C'],
  ['Testar / reprocessar', 'POST de teste/retry — default-deny no preview', 'A'],
];

function text(value) {
  return String(value ?? '').trim();
}

/** Resumo curto da anomalia, sem inventar campo: usa o que o backend entrega. */
function anomalySummary(event) {
  const bits = [];
  const origin = event.dominant_src_ip || event.top_src_ip;
  const target = event.target_ip || event.target_cidr || event.top_dst_ip;
  if (origin) bits.push(`origem ${origin}`);
  if (target) bits.push(`alvo ${target}`);
  if (event.protocol || event.decoder) bits.push(text(event.protocol || event.decoder).toLowerCase());
  if (event.target_port) bits.push(`porta ${event.target_port}`);
  if (event.peak_value != null) bits.push(`pico ${fmtNumber(event.peak_value)} ${text(event.metric_unit)}`.trim());
  return bits.join(' · ') || 'evento sem resumo estruturado';
}

function toAnomalyRows(items) {
  return (Array.isArray(items) ? items : []).map((event) => ({
    key: `anomaly-${event.id}`,
    source: 'anomaly',
    sourceLabel: 'Anomalia',
    severity: text(event.severity || 'info').toLowerCase(),
    status: text(event.status || 'active').toLowerCase(),
    title: text(event.vector_name || event.decoder || 'Anomalia'),
    summary: anomalySummary(event),
    entity: text(event.target_cidr || event.target_ip || event.top_src_ip || event.top_dst_ip) || '—',
    sensor: text(event.sensor_name) || '—',
    firstSeen: event.started_at || event.created_at || '',
    lastSeen: event.last_seen_at || event.updated_at || '',
    count: Number(event.detail_count || event.flow_count || event.unique_dst_ips || 0),
    anomalyId: Number(event.id),
    executionIds: [],
    announcementIds: [],
    connectorIds: [],
  }));
}

function toBgpRows(items) {
  return (Array.isArray(items) ? items : [])
    .filter((item) => BGP_ATTENTION.includes(text(item.status).toLowerCase()))
    .map((item) => {
      const status = text(item.status).toLowerCase();
      return {
        key: `bgp-${item.id}`,
        source: 'bgp',
        sourceLabel: 'BGP',
        severity: ['failed', 'failed_withdraw', 'peer_down'].includes(status) ? 'critical' : 'warning',
        status,
        title: text(item.attack_vector_name) || 'Anúncio BGP',
        summary: text(item.last_error || item.response_profile_name || item.connector_name) || 'sem detalhe adicional',
        entity: text(item.target_prefix || item.dst_prefix || item.dst_ip) || '—',
        sensor: text(item.connector_name) || (item.connector_id ? `#${item.connector_id}` : '—'),
        firstSeen: item.created_at || '',
        lastSeen: item.updated_at || '',
        count: 1,
        anomalyId: item.anomaly_id != null ? Number(item.anomaly_id) : null,
        announcementId: Number(item.id),
        executionIds: item.source === 'automatic_orchestrator' && item.source_id ? [Number(item.source_id)] : [],
        connectorIds: item.connector_id != null ? [Number(item.connector_id)] : [],
      };
    });
}

function toMitigationRows(items) {
  return (Array.isArray(items) ? items : [])
    .filter((item) => MITIGATION_ATTENTION.includes(text(item.status).toLowerCase()))
    .map((item) => {
      const status = text(item.status).toLowerCase();
      return {
        key: `mitigation-${item.id}`,
        source: 'mitigation',
        sourceLabel: 'Mitigação',
        severity: status === 'failed' ? 'critical' : 'warning',
        status,
        title: text(item.vector) || 'Mitigação automática',
        summary: text(item.error_message || item.policy_reason) || 'sem motivo registrado',
        entity: item.anomaly_id != null ? `anomalia #${item.anomaly_id}` : '—',
        sensor: text(item.connector_type) || (item.connector_id ? `#${item.connector_id}` : '—'),
        firstSeen: item.created_at || '',
        lastSeen: item.updated_at || '',
        count: 1,
        anomalyId: item.anomaly_id != null ? Number(item.anomaly_id) : null,
        executionId: Number(item.id),
        announcementIds: [],
        connectorIds: item.connector_id != null ? [Number(item.connector_id)] : [],
      };
    });
}

function toCollectorRows(items) {
  return (Array.isArray(items) ? items : [])
    .filter((item) => COLLECTOR_ATTENTION.includes(text(item.status).toLowerCase()))
    .map((item) => ({
      key: `collector-${item.sensor_id ?? item.sensor ?? item.exporter_ip ?? 'unknown'}`,
      source: 'collector',
      sourceLabel: 'Coletor',
      severity: 'warning',
      status: text(item.status).toLowerCase(),
      title: 'Ingestão de fluxo',
      summary: item.last_flow_time
        ? `último flow ${fmtTime(item.last_flow_time)}`
        : 'sem flow recente registrado',
      entity: text(item.sensor || item.exporter_ip) || '—',
      sensor: text(item.sensor || item.collector || item.exporter_ip) || '—',
      firstSeen: '',
      lastSeen: item.last_flow_time || item.last_insert_at || '',
      count: 1,
      anomalyId: null,
      executionIds: [],
      announcementIds: [],
      connectorIds: [],
    }));
}

function FeedChip({ label, state, count, hint }) {
  const tone = state === 'ok' ? 'ok' : state === 'error' ? 'warn' : 'unk';
  return (
    <span className={`chip ${tone}`} title={hint || undefined}>
      <StatusDot tone={state === 'ok' ? 'success' : state === 'error' ? 'critical' : 'info'} />
      <span>{label}</span>
      <b>{state === 'error' ? 'indisponível' : state === 'loading' ? '…' : fmtNumber(count ?? 0)}</b>
    </span>
  );
}

export default function Alerts({ onNavigate }) {
  const [statusFilter, setStatusFilter] = useState('active');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [entityFilter, setEntityFilter] = useState('');
  const [search, setSearch] = useState('');
  const [seenAt, setSeenAt] = useState({});

  const anomalies = useApi('/api/anomalies/active?limit=1000');
  const announcements = useApi('/api/bgp/announcements?limit=500');
  const executions = useApi('/api/mitigation/executions?limit=500');
  const collectors = useApi('/api/collectors/health');

  const feeds = [
    { key: 'anomaly', label: 'Anomalias', query: anomalies },
    { key: 'bgp', label: 'BGP', query: announcements },
    { key: 'mitigation', label: 'Mitigação', query: executions },
    { key: 'collector', label: 'Coletores', query: collectors },
  ];

  // Freshness por fonte: registra o horário em que cada feed respondeu.
  useEffect(() => {
    const updates = {};
    for (const feed of feeds) {
      if (feed.query.data) updates[feed.key] = new Date().toISOString();
    }
    if (Object.keys(updates).length) setSeenAt((current) => ({ ...current, ...updates }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anomalies.data, announcements.data, executions.data, collectors.data]);

  const anomalyRows = useMemo(() => toAnomalyRows(anomalies.data?.items), [anomalies.data]);
  const bgpRows = useMemo(() => toBgpRows(announcements.data?.items), [announcements.data]);
  const mitigationRows = useMemo(() => toMitigationRows(executions.data?.items), [executions.data]);
  const collectorRows = useMemo(() => toCollectorRows(collectors.data?.items), [collectors.data]);

  /**
   * Correlação compacta usando APENAS vínculos provados pelos campos reais:
   * execução.anomaly_id, announcement.source_id (execução) e announcement.anomaly_id.
   * Nada é inferido quando o campo não existe.
   */
  const correlated = useMemo(() => {
    const executionsByAnomaly = new Map();
    for (const execution of executions.data?.items ?? []) {
      if (execution.anomaly_id == null) continue;
      const id = Number(execution.anomaly_id);
      executionsByAnomaly.set(id, [...(executionsByAnomaly.get(id) ?? []), Number(execution.id)]);
    }
    const announcementsByAnomaly = new Map();
    const announcementsByExecution = new Map();
    for (const announcement of announcements.data?.items ?? []) {
      if (announcement.anomaly_id != null) {
        const id = Number(announcement.anomaly_id);
        announcementsByAnomaly.set(id, [...(announcementsByAnomaly.get(id) ?? []), Number(announcement.id)]);
      }
      if (announcement.source === 'automatic_orchestrator' && announcement.source_id) {
        const id = Number(announcement.source_id);
        announcementsByExecution.set(id, [...(announcementsByExecution.get(id) ?? []), Number(announcement.id)]);
      }
    }
    const executionsById = new Map((executions.data?.items ?? []).map((item) => [Number(item.id), item]));

    return (row) => {
      if (row.source === 'anomaly') {
        return {
          executions: executionsByAnomaly.get(row.anomalyId) ?? [],
          announcements: announcementsByAnomaly.get(row.anomalyId) ?? [],
          connectors: [],
        };
      }
      if (row.source === 'mitigation') {
        const announcementIds = announcementsByExecution.get(row.executionId) ?? [];
        const connectorIds = new Set(row.connectorIds ?? []);
        for (const id of announcementIds) {
          const announcement = (announcements.data?.items ?? []).find((item) => Number(item.id) === id);
          if (announcement?.connector_id != null) connectorIds.add(Number(announcement.connector_id));
        }
        return { executions: row.executionId ? [row.executionId] : [], announcements: announcementIds, connectors: [...connectorIds] };
      }
      if (row.source === 'bgp') {
        const executionIds = row.executionIds ?? [];
        const anomalyIds = new Set(row.anomalyId != null ? [row.anomalyId] : []);
        for (const id of executionIds) {
          const execution = executionsById.get(id);
          if (execution?.anomaly_id != null) anomalyIds.add(Number(execution.anomaly_id));
        }
        return { executions: executionIds, announcements: row.announcementId ? [row.announcementId] : [], connectors: row.connectorIds ?? [], anomalyIds: [...anomalyIds] };
      }
      return { executions: [], announcements: [], connectors: [] };
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [executions.data, announcements.data]);

  const allRows = useMemo(
    () => [...anomalyRows, ...mitigationRows, ...bgpRows, ...collectorRows],
    [anomalyRows, mitigationRows, bgpRows, collectorRows],
  );

  const entities = useMemo(
    () => [...new Set(allRows.map((row) => text(row.sensor)).filter((value) => value && value !== '—'))].sort(),
    [allRows],
  );

  const visible = useMemo(() => {
    const term = search.trim().toLowerCase();
    return allRows
      .filter((row) => {
        if (statusFilter === 'active' && !['active', 'acknowledged'].includes(row.status)) return false;
        if (statusFilter === 'acknowledged' && row.status !== 'acknowledged') return false;
        if (severityFilter && row.severity !== severityFilter) return false;
        if (sourceFilter && row.source !== sourceFilter) return false;
        if (entityFilter && row.sensor !== entityFilter) return false;
        if (term) {
          const haystack = `${row.title} ${row.summary} ${row.entity} ${row.sensor} ${row.status} ${row.sourceLabel}`.toLowerCase();
          if (!haystack.includes(term)) return false;
        }
        return true;
      })
      .sort((left, right) => {
        const diff = (SEVERITY_RANK[left.severity] ?? 3) - (SEVERITY_RANK[right.severity] ?? 3);
        if (diff !== 0) return diff;
        return String(right.lastSeen || '').localeCompare(String(left.lastSeen || ''));
      });
  }, [allRows, statusFilter, severityFilter, sourceFilter, entityFilter, search]);

  const criticals = allRows.filter((row) => row.severity === 'critical').length;
  const warnings = allRows.filter((row) => row.severity === 'warning').length;
  const activeRows = allRows.filter((row) => row.status === 'active').length;
  const acknowledgedRows = allRows.filter((row) => row.status === 'acknowledged').length;
  const failedFeeds = feeds.filter((feed) => feed.query.error);

  return (
    <div className="main-content">
      <div className="page-head">
        <div>
          <h2>Alertas</h2>
          <p>
            Central operacional agregadora — anomalias, mitigações, announcements e coletores que precisam de atenção
            (somente leitura)
          </p>
        </div>
        <div className="page-head-actions">
          <Badge tone={failedFeeds.length ? 'warning' : 'success'}>
            <StatusDot tone={failedFeeds.length ? 'warning' : 'success'} />
            {failedFeeds.length ? `${failedFeeds.length}/4 fonte(s) com falha` : '4/4 fontes ok'}
          </Badge>
          <ReadOnlyAction label="Reconhecer alertas" reason="ack/close/mitigate continuam bloqueados no preview" policy="C" />
        </div>
      </div>

      {/* Feeds independentes: uma fonte com erro não derruba a tela nem zera a fila. */}
      <div className="chip-row" style={{ padding: '0 0 10px' }}>
        {feeds.map((feed) => (
          <FeedChip
            key={feed.key}
            label={feed.label}
            state={feed.query.error ? 'error' : feed.query.loading ? 'loading' : 'ok'}
            count={(feed.query.data?.items ?? []).length}
            hint={feed.query.error ? `${feed.query.error}${seenAt[feed.key] ? ` · último sucesso ${fmtTime(seenAt[feed.key])}` : ' · sem leitura bem-sucedida nesta sessão'}` : undefined}
          />
        ))}
      </div>

      {failedFeeds.length ? (
        <div className="alert-banner" style={{ borderLeftColor: 'var(--warning)' }}>
          <Badge tone="warning">Fonte indisponível</Badge>
          <div>
            <b>{failedFeeds.map((feed) => feed.label).join(' · ')}</b>
            <span>{failedFeeds.map((feed) => feed.query.error).join(' | ')}</span>
          </div>
        </div>
      ) : null}

      <section className="metrics-grid wide">
        <div className="metric-card rail-critical"><span>Críticos</span><strong>{fmtNumber(criticals)}</strong><small>severidade critical na fila</small></div>
        <div className="metric-card rail-warning"><span>Warnings</span><strong>{fmtNumber(warnings)}</strong><small>severidade warning na fila</small></div>
        <div className="metric-card rail-info"><span>Ativos</span><strong>{fmtNumber(activeRows)}</strong><small>status active (≠ tráfego acontecendo)</small></div>
        <div className="metric-card"><span>Reconhecidos</span><strong>{fmtNumber(acknowledgedRows)}</strong><small>status acknowledged</small></div>
        <div className="metric-card rail-critical"><span>Anomalias ativas</span><strong>{fmtNumber(anomalyRows.length)}</strong><small>/api/anomalies/active</small></div>
        <div className="metric-card rail-warning"><span>Mitigações com problema</span><strong>{fmtNumber(mitigationRows.length)}</strong><small>failed · blocked</small></div>
        <div className="metric-card rail-critical"><span>Announcements com atenção</span><strong>{fmtNumber(bgpRows.length)}</strong><small>pending · failed · peer_down</small></div>
        <div className="metric-card rail-warning"><span>Coletores unhealthy</span><strong>{fmtNumber(collectorRows.length)}</strong><small>atrasado · sem flow recente</small></div>
      </section>

      <Panel
        title="Fila operacional"
        subtitle="uma fila única, ordenada por severidade e última ocorrência · cada item mantém a origem · a fila respeita os filtros; os KPIs resumem a amostra das 4 fontes"
        badge={`${visible.length}/${allRows.length}`}
        filters={(
          <div className="filter-row">
            <label>
              Status
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                <option value="active">Ativos e reconhecidos</option>
                <option value="acknowledged">Somente reconhecidos</option>
                <option value="all">Todos</option>
              </select>
            </label>
            <label>
              Severidade
              <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                <option value="">Todas</option>
                {SEVERITIES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label>
              Fonte
              <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
                <option value="">Todas</option>
                {SOURCES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
              </select>
            </label>
            <label>
              Sensor / fonte
              <select value={entityFilter} onChange={(event) => setEntityFilter(event.target.value)}>
                <option value="">Todos</option>
                {entities.map((entity) => <option key={entity} value={entity}>{entity}</option>)}
              </select>
            </label>
            <label>
              Busca
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="título, alvo, resumo, status" />
            </label>
          </div>
        )}
      >
        {allRows.length === 0 && feeds.some((feed) => feed.query.loading) ? <Loading /> : null}
        {allRows.length === 0 && !feeds.some((feed) => feed.query.loading) && !failedFeeds.length ? (
          <EmptyState title="Nenhum alerta precisa de atenção agora" hint="As quatro fontes responderam e não há anomalia ativa, falha de mitigação, announcement pendente ou coletor unhealthy." />
        ) : null}
        {allRows.length === 0 && failedFeeds.length ? (
          <EmptyState title="Sem dados das fontes que falharam" hint="A fila está vazia porque as fontes acima não responderam — o erro não foi convertido em zero." />
        ) : null}
        {allRows.length > 0 ? (
          <Table
            columns={[
              { key: 'severity', label: 'Severidade', render: (row) => <Badge tone={stateTone(row.severity)}>{row.severity}</Badge> },
              { key: 'source', label: 'Fonte', render: (row) => <span className="mono-small">{row.sourceLabel}</span> },
              { key: 'title', label: 'Alerta / entidade', render: (row) => (
                <>
                  <b>{row.title}</b>
                  <small className="mono-small">{row.entity}</small>
                </>
              ) },
              { key: 'summary', label: 'Resumo', render: (row) => <span className="ellipsis" title={`${row.summary}`}>{row.summary}</span> },
              { key: 'sensor', label: 'Sensor / fonte', render: (row) => row.sensor },
              { key: 'status', label: 'Status', render: (row) => <Badge tone={stateTone(row.status)}>{row.status}</Badge> },
              { key: 'correlation', label: 'Correlação', render: (row) => {
                const links = correlated(row);
                const hasAny = (links.executions?.length || links.announcements?.length || links.connectors?.length || links.anomalyIds?.length);
                if (!hasAny) return <span className="mono-small">sem vínculo comprovado</span>;
                return (
                  <span className="link-row">
                    {links.executions?.slice(0, 2).map((id) => (
                      <EntityLink key={`e${id}`} label={`Exec #${id}`} onClick={() => onNavigate('mitigation', { kind: 'execution', id })} />
                    ))}
                    {links.announcements?.slice(0, 2).map((id) => (
                      <EntityLink key={`a${id}`} label={`BGP #${id}`} onClick={() => onNavigate('bgp', { kind: 'announcement', id })} />
                    ))}
                    {links.connectors?.slice(0, 2).map((id) => (
                      <EntityLink key={`c${id}`} label={`Conector #${id}`} onClick={() => onNavigate('bgp', { kind: 'connector', id })} />
                    ))}
                  </span>
                );
              } },
              { key: 'lastSeen', label: 'Última ocorrência', render: (row) => fmtTime(row.lastSeen) },
              { key: 'firstSeen', label: 'Primeira ocorrência', render: (row) => fmtTime(row.firstSeen) },
              { key: 'count', label: 'Eventos', render: (row) => fmtNumber(row.count) },
              { key: 'action', label: 'Investigar', render: (row) => {
                if (row.source === 'anomaly' && row.anomalyId != null) {
                  return <EntityLink label="Abrir anomalia" onClick={() => onNavigate('anomalies', { kind: 'anomaly', id: row.anomalyId })} />;
                }
                if (row.source === 'mitigation' && row.executionId != null) {
                  return <EntityLink label="Abrir execução" onClick={() => onNavigate('mitigation', { kind: 'execution', id: row.executionId })} />;
                }
                if (row.source === 'bgp' && row.announcementId != null) {
                  return <EntityLink label="Abrir announcement" onClick={() => onNavigate('bgp', { kind: 'announcement', id: row.announcementId })} />;
                }
                if (row.source === 'collector') {
                  return <EntityLink label="Abrir sensores" onClick={() => onNavigate('sensors', null)} />;
                }
                return <span className="mono-small">—</span>;
              } },
            ]}
            rows={visible}
            keyFor={(row) => row.key}
            empty="Nenhum alerta corresponde aos filtros atuais."
          />
        ) : null}
      </Panel>

      <div className="two-columns">
        <Panel title="Semântica das fontes" subtitle="a tela não fortalece evidência">
          <ul className="hint-list" style={{ padding: '10px 18px 12px' }}>
            <li>alerta ativo <b>≠</b> tráfego ainda acontecendo</li>
            <li>anomalia <b>≠</b> ataque confirmado</li>
            <li>mitigação solicitada <b>≠</b> mitigação aplicada</li>
            <li>policy permitiu <b>≠</b> announcement confirmado no roteador</li>
            <li>peer established <b>≠</b> RIB remoto confirmado</li>
            <li>RIB remoto <b>≠</b> dataplane confirmado</li>
            <li>collector unhealthy <b>≠</b> sensor necessariamente offline</li>
          </ul>
        </Panel>

        <Panel title="Ações bloqueadas no preview" subtitle="nenhuma escrita liberada por conveniência" badge={READ_ONLY_ACTIONS.length} badgeTone="warning">
          <div className="link-row" style={{ padding: '10px 12px 14px' }}>
            {READ_ONLY_ACTIONS.map(([label, reason, policy]) => (
              <ReadOnlyAction key={label} label={label} reason={reason} policy={policy} />
            ))}
          </div>
          <p className="hint" style={{ padding: '0 12px 12px' }}>
            Interface/ifIndex: nenhuma fonte de Alertas expõe interface de flow hoje. Quando o resolver único do
            BLOCO 3 existir, campos de interface vindos de flow entram por ele — nunca com tradução local.
          </p>
        </Panel>
      </div>
    </div>
  );
}
