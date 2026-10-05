import React, { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  EmptyState,
  EntityLink,
  ErrorBox,
  EvidenceLevel,
  KeyValues,
  Loading,
  Pagination,
  Panel,
  ReadOnlyAction,
  StatusDot,
  Table,
  Timeline,
  fmtNumber,
  fmtTime,
  stateTone,
  useApi,
} from './shared.jsx';

/**
 * BLOCO 1 — Mitigação (PREVIEW V2, somente leitura).
 *
 * Todos os campos vêm do backend real: /api/mitigation/executions,
 * /api/mitigation/automation/health, /api/bgp/response-profiles,
 * /api/bgp/port-policies, /api/bgp/protected-prefixes, /api/bgp/announcements,
 * /api/rtbh/*. Nenhuma ação de escrita é oferecida.
 */

const EXECUTION_STATUSES = [
  'generated', 'queued', 'applying', 'active', 'failed',
  'withdraw_pending', 'withdrawn', 'expired', 'blocked', 'cancelled',
];

const RTBH_STATUS_HINT = {
  REVIEW_REQUIRED: 'aguardando revisão humana — nenhum anúncio realizado',
  DRY_RUN: 'simulação apenas — nenhum anúncio realizado',
  APPROVED: 'aprovado no fluxo RTBH (a versão atual não executa anúncio)',
  REJECTED: 'rejeitado pelo operador',
};

function ageLabel(value) {
  if (!value) return 'sem carimbo';
  const ts = Date.parse(value);
  if (!Number.isFinite(ts)) return 'sem carimbo';
  const seconds = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (seconds < 60) return `há ${seconds}s`;
  if (seconds < 3600) return `há ${Math.round(seconds / 60)}min`;
  if (seconds < 86400) return `há ${Math.round(seconds / 3600)}h`;
  return `há ${Math.round(seconds / 86400)}d`;
}

function shortJson(value) {
  if (value == null) return '—';
  if (typeof value === 'string') return value || '—';
  try {
    const text = JSON.stringify(value);
    return text.length > 160 ? `${text.slice(0, 157)}…` : text;
  } catch (_) {
    return '—';
  }
}

function Tabs({ value, onChange, tabs }) {
  return (
    <nav className="page-tabs" role="tablist" aria-label="Seções da mitigação">
      {tabs.map(([id, label, badge]) => (
        <button
          key={id}
          type="button"
          role="tab"
          aria-selected={value === id}
          className={value === id ? 'active' : ''}
          onClick={() => onChange(id)}
        >
          {label}{badge != null ? <em>{badge}</em> : null}
        </button>
      ))}
    </nav>
  );
}

function Kpi({ label, value, hint, tone = '' }) {
  return (
    <div className={`metric-card ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {hint ? <small>{hint}</small> : null}
    </div>
  );
}

/** Announcement associado a uma execução — mesma regra do backend. */
function resolveAnnouncement(execution, announcements) {
  if (!execution) return null;
  const direct = execution.apply_result?.announcement_id
    || execution.apply_result?.announcement?.id
    || null;
  if (direct) {
    const found = announcements.find((item) => Number(item.id) === Number(direct));
    if (found) return found;
  }
  return announcements.find((item) => (
    (item.source === 'automatic_orchestrator' && String(item.source_id) === String(execution.id))
    || (execution.idempotency_key && item.mitigation_key === execution.idempotency_key)
  )) ?? null;
}

function ExecutionDrawer({ execution, announcements, connectors, onClose, onNavigate }) {
  const announcement = resolveAnnouncement(execution, announcements);
  const detail = useApi(`/api/bgp/announcements/${announcement?.id ?? 0}`, {
    enabled: Boolean(announcement?.id),
    deps: [announcement?.id],
  });
  const connector = connectors.find((item) => Number(item.id) === Number(execution?.connector_id)) ?? null;
  const events = Array.isArray(detail.data?.events) ? detail.data.events : [];
  const checks = detail.data?.status_details?.checks ?? {};
  const details = detail.data?.status_details ?? {};

  return (
    <div className="overlay" onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Execução ${execution.id}`}>
        <header>
          <div>
            <span className="eyebrow">MITIGATION EXECUTION</span>
            <h2>Execução #{execution.id}</h2>
            <p>anomalia {execution.anomaly_id ?? '—'} · criada {fmtTime(execution.created_at)}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fechar">×</button>
        </header>

        <section>
          <h4>1 · Resumo</h4>
          <KeyValues items={[
            ['status', <Badge tone={stateTone(execution.status)}>{execution.status || '—'}</Badge>],
            ['anomalia', execution.anomaly_id
              ? <EntityLink label={`#${execution.anomaly_id}`} title="Abrir em Anomalias" onClick={() => onNavigate('anomalies', { kind: 'anomaly', id: execution.anomaly_id })} />
              : '—'],
            ['vetor', execution.vector || '—'],
            ['ação', execution.action || '—'],
            ['origem', execution.automatic ? 'automática' : 'manual'],
            ['atualizada', fmtTime(execution.updated_at)],
          ]} />
        </section>

        <section>
          <h4>2 · Decisão</h4>
          <KeyValues items={[
            ['policy reason', execution.policy_reason || '—'],
            ['decision source', execution.decision_source || '—'],
            ['profile', execution.profile || execution.profile_id || '—'],
            ['candidate kind', execution.candidate_kind || '—'],
            ['template', execution.candidate?.template || '—'],
            ['manual only', execution.candidate?.manual_only ? 'sim' : 'não'],
            ['allow auto', execution.candidate?.allow_auto ? 'sim' : 'não'],
            ['gates', shortJson(execution.gates)],
          ]} />
        </section>

        <section>
          <h4>3 · Execução</h4>
          <KeyValues items={[
            ['conector', execution.connector_id
              ? <EntityLink label={`#${execution.connector_id}${connector ? ` · ${connector.name}` : ''}`} title="Abrir em BGP / Conectores" onClick={() => onNavigate('bgp', { kind: 'connector', id: execution.connector_id })} />
              : '—'],
            ['tipo do conector', execution.connector_type || '—'],
            ['ttl', execution.ttl_seconds != null ? `${execution.ttl_seconds}s` : '—'],
            ['aplicado em', fmtTime(execution.applied_at)],
            ['expira em', fmtTime(execution.expires_at)],
            ['retirado em', fmtTime(execution.withdrawn_at)],
            ['retries', `${execution.retry_count ?? 0}/${execution.max_retries ?? 0}`],
            ['erro', execution.error_message || execution.error_code || '—'],
          ]} />
          <div className="command-block">
            <span>comando anunciado</span>
            <code>{execution.command || '—'}</code>
            <span>comando de retirada</span>
            <code>{execution.withdraw_command || '—'}</code>
            <span>match normalizado</span>
            <code>{shortJson(execution.normalized_match)}</code>
          </div>
        </section>

        <section>
          <h4>4 · Announcement</h4>
          {announcement ? (
            <>
              <KeyValues items={[
                ['announcement', <EntityLink label={`#${announcement.id}`} title="Abrir em BGP / Conectores" onClick={() => onNavigate('bgp', { kind: 'announcement', id: announcement.id })} />],
                ['status', <Badge tone={stateTone(announcement.status)}>{announcement.status || '—'}</Badge>],
                ['route type', announcement.route_type || '—'],
                ['requested mode', announcement.requested_mode || '—'],
                ['policy decision', `${announcement.policy_decision || '—'} / ${announcement.policy_severity || '—'}`],
                ['confirmação', announcement.confirmation_level || '—'],
                ['anunciado em', fmtTime(announcement.announced_at || announcement.advertised_at)],
                ['expira em', fmtTime(announcement.expires_at)],
                ['retirado em', fmtTime(announcement.withdrawn_at)],
                ['último erro', announcement.last_error || '—'],
              ]} />
              <p className="hint">
                <b>{announcement.confirmation_level || 'sem confirmação'}</b> é o nível registrado pelo sistema.
                Não significa regra presente no RIB remoto nem bloqueio confirmado no dataplane.
              </p>
            </>
          ) : (
            <EmptyState title="Sem announcement associado" hint="Nenhum registro em bgp_announcements referencia esta execução (source=automatic_orchestrator/source_id ou mitigation_key)." />
          )}
        </section>

        <section>
          <h4>5 · BGP / readiness (evidência do momento do anúncio)</h4>
          {announcement && detail.data ? (
            <>
              <div className="chip-row">
                {[
                  ['serviço', checks.service_ok],
                  ['listener', checks.listener_ok],
                  ['pipe', checks.pipe_ok],
                  ['flow spec', checks.flowspec_ok],
                  ['bgp', checks.bgp_ok],
                  ['transporte', checks.transport_ready],
                  ['caminho de entrega', checks.delivery_path_ready],
                ].map(([label, ok]) => (
                  <span key={label} className={`chip ${ok ? 'ok' : 'warn'}`}>
                    <StatusDot tone={ok ? 'success' : 'warning'} />
                    <span>{label}</span>
                    <b>{ok ? 'ok' : 'pendente'}</b>
                  </span>
                ))}
              </div>
              <KeyValues items={[
                ['bgp state', details.bgp_state || announcement.peer_state || '—'],
                ['flowspec state', details.flowspec_state || '—'],
                ['pipe state', details.pipe_state || '—'],
                ['peer state', announcement.peer_state || '—'],
                ['reader ativo', details.reader_active ? 'sim' : 'não'],
                ['delivery path', `${details.delivery_path_reason || '—'} (${details.delivery_path_source || '—'})`],
              ]} />
              {Array.isArray(details.messages) && details.messages.length ? (
                <ul className="hint-list">{details.messages.map((message) => <li key={message}>{message}</li>)}</ul>
              ) : null}
            </>
          ) : (
            <EmptyState title="Evidência de readiness não disponível" hint="Só aparece quando existe announcement associado com status_details persistido." />
          )}
        </section>

        <section>
          <h4>6 · Evidência da cadeia</h4>
          <div className="evidence-levels">
            <EvidenceLevel verified label="Mitigação solicitada" detail={`execução #${execution.id} criada e persistida`} />
            <EvidenceLevel verified={Boolean(execution.policy_reason)} label="Policy decidiu" detail={execution.policy_reason || 'sem registro'} />
            <EvidenceLevel verified={Boolean(execution.command)} label="Comando gerado" detail={execution.command ? 'renderizado pelo backend' : 'sem comando'} />
            <EvidenceLevel verified={Boolean(announcement)} label="Entregue ao ExaBGP" detail={announcement?.status_details?.checks?.delivery_path_ready ? 'caminho de entrega pronto' : 'sem confirmação de entrega'} />
            <EvidenceLevel verified={String(announcement?.peer_state || '').toLowerCase() === 'established'} label="Peer BGP established" detail={announcement?.peer_state || '—'} />
            <EvidenceLevel verified={false} label="Regra no RIB remoto" detail="não há endpoint que comprove" />
            <EvidenceLevel verified={false} label="Efeito no dataplane" detail="não há endpoint que comprove" />
          </div>
        </section>

        <section>
          <h4>7 · Timeline real</h4>
          {detail.loading && announcement ? <Loading /> : null}
          {detail.error ? <ErrorBox message={detail.error} /> : null}
          {!detail.loading && !detail.error ? (
            events.length ? (
              <Timeline items={events.map((event) => ({
                title: `${event.event_type} · ${event.message || ''}`.trim(),
                at: fmtTime(event.created_at),
                detail: event.created_by ? `por ${event.created_by}` : null,
                tone: stateTone(event.event_type),
              }))} />
            ) : (
              <Timeline items={[
                { title: 'Execução criada', at: fmtTime(execution.created_at), tone: 'info' },
                { title: 'Aplicada no conector', at: fmtTime(execution.applied_at), tone: 'warning' },
                { title: 'Expiração prevista', at: fmtTime(execution.expires_at), tone: 'info' },
              ]} />
            )
          ) : null}
        </section>

        <footer>
          <ReadOnlyAction label="Aplicar mitigação" reason="POST /api/anomalies/{id}/mitigation/apply — bloqueado no preview" policy="C" />
          <ReadOnlyAction label="Rejeitar candidato" reason="POST de escrita — bloqueado no preview" policy="C" />
          <button type="button" className="control" onClick={onClose}>Fechar</button>
        </footer>
      </aside>
    </div>
  );
}

export default function Mitigation({ focus, onNavigate }) {
  const [tab, setTab] = useState('AGORA');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');
  const [rtbhOffset, setRtbhOffset] = useState(0);
  const [openExecutionId, setOpenExecutionId] = useState(null);
  /**
   * Cross-link de outra página (ex.: announcement → execução): a navegação
   * entrega `{ kind, id }`; a linha pode não estar carregada ainda, então
   * esperamos a lista trazer o id antes de abrir o drawer.
   */
  const [pendingExecutionId, setPendingExecutionId] = useState(null);
  const [pendingMiss, setPendingMiss] = useState(null);

  const health = useApi('/api/mitigation/automation/health');
  const executions = useApi('/api/mitigation/executions?limit=400');
  const connectors = useApi('/api/bgp/connectors?include_disabled=true');
  const profiles = useApi('/api/bgp/response-profiles?include_disabled=true');
  const protectedPrefixes = useApi('/api/bgp/protected-prefixes');
  const portPolicies = useApi('/api/bgp/port-policies');
  const announcements = useApi('/api/bgp/announcements?limit=500');
  const rtbhOverview = useApi('/api/rtbh/overview');
  const rtbhProviders = useApi('/api/rtbh/providers');
  const rtbhCandidates = useApi(`/api/rtbh/candidates?limit=50&offset=${rtbhOffset}`, { deps: [rtbhOffset] });

  const executionList = executions.data?.items ?? [];
  const summary = executions.data?.summary ?? {};
  const connectorList = connectors.data?.items ?? [];
  const profileList = profiles.data?.items ?? [];
  const prefixList = protectedPrefixes.data?.items ?? [];
  const portPolicyList = portPolicies.data?.items ?? [];
  const announcementList = announcements.data?.items ?? [];
  const activeAnnouncements = announcementList.filter((item) => item.status === 'advertised');
  const unhealthyConnectors = connectorList.filter((item) => String(item.bgp_state || '').toLowerCase() !== 'established');
  const invalidProfiles = profileList.filter((item) => item.validation_status && item.validation_status !== 'valid');

  const blockedByReason = useMemo(() => {
    const counts = new Map();
    executionList.filter((item) => item.status === 'blocked').forEach((item) => {
      const key = item.policy_reason || '(sem motivo)';
      counts.set(key, (counts.get(key) ?? 0) + 1);
    });
    return [...counts].sort((a, b) => b[1] - a[1]);
  }, [executionList]);

  const filteredExecutions = useMemo(() => {
    const term = search.trim().toLowerCase();
    return executionList.filter((item) => {
      if (statusFilter && item.status !== statusFilter) return false;
      if (!term) return true;
      return String(item.anomaly_id ?? '').includes(term)
        || String(item.id).includes(term)
        || String(item.vector ?? '').toLowerCase().includes(term)
        || String(item.policy_reason ?? '').toLowerCase().includes(term);
    });
  }, [executionList, search, statusFilter]);

  const focusExecution = focus?.kind === 'execution' && focus.item ? focus.item : null;
  const openExecution = (openExecutionId != null
    ? executionList.find((item) => Number(item.id) === Number(openExecutionId))
    : null) ?? focusExecution;
  const closeExecution = () => {
    setOpenExecutionId(null);
    if (focusExecution) onNavigate('mitigation', null);
  };

  const rtbh = rtbhCandidates.data ?? {};
  const killSwitch = rtbhOverview.data?.kill_switch ?? {};

  useEffect(() => {
    if (focus?.kind !== 'execution') return;
    const id = focus.item?.id ?? focus.id;
    if (id == null) return;
    setTab('EXECUCOES');
    if (focus.item?.id) setOpenExecutionId(focus.item.id);
    else setPendingExecutionId(Number(id));
  }, [focus]);

  useEffect(() => {
    if (pendingExecutionId == null) return;
    const found = executionList.find((item) => Number(item.id) === pendingExecutionId);
    if (found) {
      setOpenExecutionId(pendingExecutionId);
      setPendingExecutionId(null);
      setPendingMiss(null);
      return;
    }
    if (!executions.loading && executions.data) {
      // Não está na amostra carregada: mostra o filtro com o id, sem inventar.
      setSearch(String(pendingExecutionId));
      setPendingMiss(pendingExecutionId);
      setPendingExecutionId(null);
    }
  }, [pendingExecutionId, executionList, executions.loading, executions.data]);

  return (
    <div className="main-content">
      <div className="page-head">
        <div>
          <h2>Mitigação</h2>
          <p>Execuções, decisão de policy, profiles, RTBH e evidência da cadeia — dados reais, somente leitura</p>
        </div>
        <div className="page-head-actions">
          <Badge tone={health.data?.worker_enabled ? 'success' : 'warning'}>
            <StatusDot tone={health.data?.worker_enabled ? 'success' : 'warning'} pulse={Boolean(health.data?.worker_enabled)} />
            worker {health.data?.worker_enabled ? 'habilitado' : 'desabilitado'}
          </Badge>
          <ReadOnlyAction label="Aplicar mitigação" reason="Ações de escrita continuam bloqueadas no preview" policy="C" />
        </div>
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          ['AGORA', 'Agora', activeAnnouncements.length],
          ['EXECUCOES', 'Execuções', executionList.length],
          ['PROFILES', 'Profiles · Policies · Protected', profileList.length],
          ['RTBH', 'RTBH', rtbh.total ?? 0],
        ]}
      />

      {tab === 'AGORA' ? (
        <>
          <section className="metrics-grid wide">
            <Kpi label="Execuções" value={fmtNumber(executions.data?.count ?? executionList.length)} hint="mitigation_executions" tone="rail-info" />
            <Kpi label="Ativas" value={fmtNumber(summary.active ?? 0)} hint="aplicadas agora" tone="rail-success" />
            <Kpi label="Bloqueadas" value={fmtNumber(summary.blocked ?? 0)} hint="policy ou gates" tone="rail-critical" />
            <Kpi label="Retiradas" value={fmtNumber(summary.withdrawn ?? 0)} hint="TTL encerrado" />
            <Kpi label="Anúncios ativos" value={fmtNumber(activeAnnouncements.length)} hint="status advertised" tone="rail-info" />
            <Kpi label="Profiles inválidos" value={fmtNumber(invalidProfiles.length)} hint="validation_status ≠ valid" tone={invalidProfiles.length ? 'rail-warning' : 'rail-success'} />
            <Kpi label="Conectores indisponíveis" value={fmtNumber(unhealthyConnectors.length)} hint="bgp_state ≠ established" tone={unhealthyConnectors.length ? 'rail-critical' : 'rail-success'} />
            <Kpi label="Freshness" value={ageLabel(health.data?.last_execution_at)} hint="última execução" tone="rail-info" />
          </section>

          <div className="two-columns">
            <Panel title="Automação" subtitle="orchestrator · worker · jobs" badge={health.error ? 'Indisponível' : 'ao vivo'} badgeTone={health.error ? 'warning' : 'success'}>
              {health.loading ? <Loading /> : health.error ? <ErrorBox message={health.error} /> : (
                <>
                  <div className="chip-row" style={{ padding: '0 12px 10px' }}>
                    <span className={`chip ${health.data?.thread_alive ? 'ok' : 'warn'}`}>
                      <StatusDot tone={health.data?.thread_alive ? 'success' : 'warning'} />
                      <span>orquestrador</span><b>{health.data?.thread_alive ? 'ativo' : 'parado'}</b>
                    </span>
                    <span className={`chip ${health.data?.worker_enabled ? 'ok' : 'warn'}`}>
                      <StatusDot tone={health.data?.worker_enabled ? 'success' : 'warning'} />
                      <span>worker</span><b>{health.data?.worker_enabled ? 'habilitado' : 'desabilitado'}</b>
                    </span>
                    <span className="chip"><span>intervalo</span><b>{health.data?.interval_seconds ?? '—'}s</b></span>
                    <span className="chip"><span>último job</span><b>{ageLabel(health.data?.last_job_at)}</b></span>
                    <span className="chip"><span>última execução</span><b>{ageLabel(health.data?.last_execution_at)}</b></span>
                    <span className="chip"><span>total</span><b>{fmtNumber(health.data?.total ?? 0)}</b></span>
                  </div>
                  <div className="kv-grid">
                    {Object.entries(health.data?.executions ?? {}).map(([key, value]) => (
                      <div key={key}><span>{key}</span><b>{fmtNumber(value)}</b></div>
                    ))}
                  </div>
                </>
              )}
            </Panel>

            <Panel title="Bloqueios por policy" subtitle="execuções com status blocked (amostra das últimas 400)" badge={blockedByReason.length}>
              {executions.loading ? <Loading /> : (
                <Table
                  columns={[
                    { key: 'reason', label: 'Motivo', render: (row) => <code>{row.reason}</code> },
                    { key: 'total', label: 'Execuções', render: (row) => fmtNumber(row.total) },
                  ]}
                  rows={blockedByReason.map(([reason, total]) => ({ reason, total }))}
                  keyFor={(row) => row.reason}
                  empty="Nenhuma execução bloqueada na amostra."
                />
              )}
            </Panel>
          </div>

          <div className="two-columns">
            <Panel title="Anúncios ativos" subtitle="status advertised · confirmation_level explícito" badge={activeAnnouncements.length} badgeTone="success">
              {announcements.loading ? <Loading /> : announcements.error ? <ErrorBox message={announcements.error} /> : (
                <Table
                  columns={[
                    { key: 'id', label: 'ID' },
                    { key: 'target_prefix', label: 'Alvo', render: (row) => <code>{row.target_prefix || row.dst_prefix || '—'}</code> },
                    { key: 'connector', label: 'Conector', render: (row) => <EntityLink label={`#${row.connector_id}`} onClick={() => onNavigate('bgp', { kind: 'connector', id: row.connector_id })} /> },
                    { key: 'confirmation_level', label: 'Confirmação', render: (row) => <Badge tone={stateTone(row.confirmation_level)}>{row.confirmation_level || '—'}</Badge> },
                    { key: 'expires_at', label: 'Expira', render: (row) => fmtTime(row.expires_at) },
                    { key: 'a', label: '', render: (row) => <EntityLink label="abrir" onClick={() => onNavigate('bgp', { kind: 'announcement', id: row.id })} /> },
                  ]}
                  rows={activeAnnouncements}
                  keyFor={(row) => row.id}
                  empty="Nenhum anúncio ativo."
                />
              )}
            </Panel>

            <Panel title="Falhas recentes" subtitle="automation health · últimos 5" badge={health.data?.recent_failures?.length ?? 0} badgeTone="warning">
              {health.loading ? <Loading /> : (
                (health.data?.recent_failures ?? []).length ? (
                  <ul className="failure-list">
                    {health.data.recent_failures.map((item) => (
                      <li key={`${item.id}-${item.at}`}>
                        <b><Badge tone="critical">failed</Badge> execução #{item.id}</b>
                        <span>anomalia {item.anomaly_id ?? '—'} · vetor {item.vector || '—'} · conector {item.connector_id ?? '—'}</span>
                        <code>{item.error || 'sem mensagem'}</code>
                        <small>{fmtTime(item.at)}</small>
                      </li>
                    ))}
                  </ul>
                ) : <EmptyState title="Sem falhas recentes na amostra" />
              )}
            </Panel>
          </div>
        </>
      ) : null}

      {tab === 'EXECUCOES' ? (
        <Panel
          title="Execuções de mitigação"
          subtitle="campos reais de mitigation_executions"
          badge={`${filteredExecutions.length}/${executionList.length}`}
          filters={(
            <div className="filter-row">
              <label>
                Status
                <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                  <option value="">Todos os status</option>
                  {EXECUTION_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
              </label>
              <label>
                Buscar
                <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="anomalia, id, vetor, motivo" />
              </label>
            </div>
          )}
        >
          {pendingMiss != null ? (
            <p className="hint" style={{ padding: '9px 12px 0' }}>
              Execução <b>#{pendingMiss}</b> não está na amostra carregada (últimas 400 execuções) — o filtro abaixo foi
              preenchido com o id para você conferir sem a UI inventar registro.
            </p>
          ) : null}
          {executions.loading ? <Loading /> : executions.error ? <ErrorBox message={executions.error} /> : (
            <Table
              onRowClick={(row) => setOpenExecutionId(row.id)}
              columns={[
                { key: 'id', label: 'ID' },
                { key: 'anomaly_id', label: 'Anomalia', render: (row) => row.anomaly_id != null ? <code>#{row.anomaly_id}</code> : '—' },
                { key: 'vector', label: 'Vetor' },
                { key: 'action', label: 'Ação', render: (row) => <code>{row.action || '—'}</code> },
                { key: 'connector_id', label: 'Conector', render: (row) => row.connector_id != null ? `#${row.connector_id}` : '—' },
                { key: 'policy_reason', label: 'Motivo', render: (row) => <span className="ellipsis" title={row.policy_reason}>{row.policy_reason || '—'}</span> },
                { key: 'status', label: 'Status', render: (row) => <Badge tone={stateTone(row.status)}>{row.status || '—'}</Badge> },
                { key: 'applied_at', label: 'Aplicado', render: (row) => fmtTime(row.applied_at) },
                { key: 'expires_at', label: 'Expira', render: (row) => fmtTime(row.expires_at) },
                { key: 'updated_at', label: 'Atualizado', render: (row) => fmtTime(row.updated_at) },
              ]}
              rows={filteredExecutions}
              keyFor={(row) => row.id}
              empty="Nenhuma execução para o filtro atual."
            />
          )}
        </Panel>
      ) : null}

      {tab === 'PROFILES' ? (
        <>
          <Panel title="Response profiles" subtitle="validation_status vem do backend" badge={`${profileList.length} profiles`}>
            {profiles.loading ? <Loading /> : profiles.error ? <ErrorBox message={profiles.error} /> : (
              <Table
                columns={[
                  { key: 'id', label: 'ID' },
                  { key: 'name', label: 'Profile' },
                  { key: 'validation_status', label: 'Validação', render: (row) => <Badge tone={stateTone(row.validation_status)}>{row.validation_status || '—'}</Badge> },
                  { key: 'connector_name', label: 'Conector', render: (row) => row.connector_name || (row.connector_id ? `#${row.connector_id}` : '—') },
                  { key: 'response_type', label: 'Tipo' },
                  { key: 'action', label: 'Ação', render: (row) => <code>{row.action || row.default_action || '—'}</code> },
                  { key: 'approval_mode', label: 'Aprovação' },
                  { key: 'rate_limit', label: 'Rate limit', render: (row) => row.rate_limit_bps ? `${fmtNumber(row.rate_limit_bps)} bps` : (row.rate_limit_value_raw || '—') },
                  { key: 'used_by_rules_count', label: 'Regras' },
                  { key: 'enabled', label: 'Ativo', render: (row) => <Badge tone={row.enabled ? 'success' : 'warning'}>{row.enabled ? 'sim' : 'não'}</Badge> },
                ]}
                rows={profileList}
                keyFor={(row) => row.id}
                empty="Nenhum profile cadastrado."
              />
            )}
          </Panel>

          <div className="two-columns">
            <Panel title="Port policies" subtitle="bgp_mitigation_port_policies" badge={portPolicyList.length}>
              {portPolicies.loading ? <Loading /> : portPolicies.error ? <ErrorBox message={portPolicies.error} /> : (
                <Table
                  columns={[
                    { key: 'id', label: 'ID' },
                    { key: 'protocol', label: 'Protocolo' },
                    { key: 'port_kind', label: 'Lado' },
                    { key: 'port_value', label: 'Porta' },
                    { key: 'is_critical', label: 'Crítica', render: (row) => <Badge tone={row.is_critical ? 'critical' : 'info'}>{row.is_critical ? 'sim' : 'não'}</Badge> },
                    { key: 'allow_port_only_auto', label: 'Auto só porta', render: (row) => (row.allow_port_only_auto ? 'sim' : 'não') },
                    { key: 'is_active', label: 'Ativa', render: (row) => <Badge tone={row.is_active ? 'success' : 'warning'}>{row.is_active ? 'sim' : 'não'}</Badge> },
                  ]}
                  rows={portPolicyList}
                  keyFor={(row) => row.id}
                  empty="Nenhuma port policy."
                />
              )}
            </Panel>

            <Panel title="Protected prefixes" subtitle="block_* por serviço protegido" badge={prefixList.length}>
              {protectedPrefixes.loading ? <Loading /> : protectedPrefixes.error ? <ErrorBox message={protectedPrefixes.error} /> : (
                <Table
                  columns={[
                    { key: 'cidr', label: 'Prefixo', render: (row) => <code>{row.cidr}</code> },
                    { key: 'name', label: 'Nome' },
                    { key: 'protection_level', label: 'Nível' },
                    { key: 'blocks', label: 'Bloqueios', render: (row) => (
                      <span className="mono-small">
                        {[
                          row.block_flowspec ? 'flowspec' : null,
                          row.block_rtbh ? 'rtbh' : null,
                          row.block_auto_rtbh ? 'auto-rtbh' : null,
                          row.block_diversion ? 'diversion' : null,
                          row.block_all_rtbh ? 'all-rtbh' : null,
                        ].filter(Boolean).join(' · ') || '—'}
                      </span>
                    ) },
                    { key: 'require_manual_rtbh', label: 'RTBH manual', render: (row) => (row.require_manual_rtbh ? 'sim' : 'não') },
                    { key: 'enabled', label: 'Ativo', render: (row) => <Badge tone={row.enabled ? 'success' : 'warning'}>{row.enabled ? 'sim' : 'não'}</Badge> },
                  ]}
                  rows={prefixList}
                  keyFor={(row) => row.id}
                  empty="Nenhum prefixo protegido."
                />
              )}
            </Panel>
          </div>
        </>
      ) : null}

      {tab === 'RTBH' ? (
        <>
          <div className="alert-banner ok">
            <Badge tone="warning">RECOMMEND_ONLY / DRY-RUN</Badge>
            <div>
              <b>Esta versão não executa anúncio RTBH.</b>
              <span>
                env <code>{killSwitch.env_var || 'RTBH_EXECUTION_ENABLED'}</code>={String(killSwitch.environment_execution_enabled)}
                {' · '}versão permite={String(killSwitch.version_allows_execution)}
                {' · '}efetivo={String(killSwitch.effective_execution)}
              </span>
            </div>
          </div>

          <section className="metrics-grid wide">
            <Kpi label="Providers" value={fmtNumber(rtbhOverview.data?.providers ?? 0)} tone="rail-info" />
            <Kpi label="Policies" value={fmtNumber(rtbhOverview.data?.policies ?? 0)} />
            <Kpi label="Candidatos" value={fmtNumber(rtbh.total ?? 0)} hint="rtbh_mitigation_candidates" tone="rail-warning" />
            {Object.entries(rtbhOverview.data?.candidate_counts ?? {}).map(([key, value]) => (
              <Kpi key={key} label={key} value={fmtNumber(value)} hint={RTBH_STATUS_HINT[key] || 'estado real do candidato'} tone={stateTone(key) === 'warning' ? 'rail-warning' : undefined} />
            ))}
          </section>

          <Panel title="Transit providers e policy" subtitle="mode/allow_auto/require_manual_approval/validation_only" badge={rtbhProviders.data?.items?.length ?? 0}>
            {rtbhProviders.loading ? <Loading /> : rtbhProviders.error ? <ErrorBox message={rtbhProviders.error} /> : (
              <Table
                columns={[
                  { key: 'id', label: 'ID' },
                  { key: 'name', label: 'Provider' },
                  { key: 'input_if', label: 'Interface' },
                  { key: 'enabled', label: 'Ativo', render: (row) => <Badge tone={row.enabled ? 'success' : 'warning'}>{row.enabled ? 'sim' : 'não'}</Badge> },
                  { key: 'mode', label: 'Modo', render: (row) => <Badge tone={stateTone(row.policy?.mode)}>{row.policy?.mode || '—'}</Badge> },
                  { key: 'allow_auto', label: 'Auto', render: (row) => (row.policy?.allow_auto ? 'sim' : 'não') },
                  { key: 'manual', label: 'Aprovação manual', render: (row) => (row.policy?.require_manual_approval ? 'obrigatória' : 'não') },
                  { key: 'validation_only', label: 'Só validação', render: (row) => (row.policy?.validation_only ? 'sim' : 'não') },
                ]}
                rows={rtbhProviders.data?.items ?? []}
                keyFor={(row) => row.id}
                empty="Nenhum provider RTBH."
              />
            )}
          </Panel>

          <Panel title="Candidatos RTBH" subtitle="candidato ≠ mitigação aplicada" badge={`${rtbh.items?.length ?? 0} de ${fmtNumber(rtbh.total ?? 0)}`}>
            {rtbhCandidates.loading ? <Loading /> : rtbhCandidates.error ? <ErrorBox message={rtbhCandidates.error} /> : (
              <>
                <Table
                  columns={[
                    { key: 'id', label: 'ID' },
                    { key: 'target_prefix', label: 'Prefixo', render: (row) => <code>{row.target_prefix}</code> },
                    { key: 'classification', label: 'Classificação' },
                    { key: 'action_type', label: 'Ação' },
                    { key: 'provider_name', label: 'Provider', render: (row) => row.provider_name || (row.provider_id ? `#${row.provider_id}` : '—') },
                    { key: 'confidence', label: 'Confiança', render: (row) => row.confidence != null ? row.confidence.toFixed(2) : '—' },
                    { key: 'collateral_risk', label: 'Colateral', render: (row) => <Badge tone={stateTone(row.collateral_risk)}>{row.collateral_risk || '—'}</Badge> },
                    { key: 'status', label: 'Status', render: (row) => (
                      <>
                        <Badge tone={stateTone(row.status)}>{row.status || '—'}</Badge>
                        <small className="mono-small">{RTBH_STATUS_HINT[row.status] || 'estado real'}</small>
                      </>
                    ) },
                    { key: 'validation_only', label: 'Só validação', render: (row) => (row.validation_only ? 'sim' : 'não') },
                    { key: 'created_at', label: 'Criado', render: (row) => fmtTime(row.created_at) },
                  ]}
                  rows={rtbh.items ?? []}
                  keyFor={(row) => row.id}
                  empty="Nenhum candidato RTBH."
                />
                <Pagination total={rtbh.total ?? 0} limit={rtbh.limit ?? 50} offset={rtbh.offset ?? 0} onChange={setRtbhOffset} />
              </>
            )}
          </Panel>
        </>
      ) : null}

      {openExecution ? (
        <ExecutionDrawer
          execution={openExecution}
          announcements={announcementList}
          connectors={connectorList}
          onClose={closeExecution}
          onNavigate={onNavigate}
        />
      ) : null}
    </div>
  );
}
