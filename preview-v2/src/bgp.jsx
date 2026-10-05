import React, { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  EmptyState,
  EntityLink,
  ErrorBox,
  EvidenceLevel,
  KeyValues,
  Loading,
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
 * BLOCO 1 — BGP / Conectores (PREVIEW V2, somente leitura).
 *
 * Fontes reais: /api/bgp/summary, /api/bgp/connectors,
 * /api/bgp/connectors/{id}/status, /api/bgp/announcements,
 * /api/bgp/announcements/{id} (com events), /api/system/exabgp/status e
 * /api/collectors/health. Nenhuma ação de escrita é oferecida.
 */

const ANNOUNCEMENT_STATUSES = [
  'dry_run', 'prepared', 'pending_approval', 'queued', 'sent', 'advertised',
  'peer_down', 'deduplicated', 'active', 'announced', 'rejected',
  'rejected_by_policy', 'withdrawn', 'expired', 'failed', 'failed_withdraw',
];

/** Níveis de confirmação conhecidos do backend (ordem = força da evidência). */
const CONFIRMATION_ORDER = [
  'withdrawn', 'expired', 'peer_established_announce_requested', 'rejected',
];

function shortJson(value) {
  if (value == null) return '—';
  if (typeof value === 'string') return value || '—';
  try {
    const text = JSON.stringify(value);
    return text.length > 200 ? `${text.slice(0, 197)}…` : text;
  } catch (_) {
    return '—';
  }
}

function Tabs({ value, onChange, tabs }) {
  return (
    <nav className="page-tabs" role="tablist" aria-label="Seções do BGP">
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

function ReadinessChip({ label, value, ok, hint }) {
  return (
    <span className={`chip ${ok === true ? 'ok' : ok === false ? 'warn' : 'unk'}`} title={hint || undefined}>
      {ok === true || ok === false ? <StatusDot tone={ok ? 'success' : 'warning'} /> : <StatusDot tone="info" />}
      <span>{label}</span>
      <b>{value}</b>
    </span>
  );
}

function ConnectorDrawer({ connector, announcements, onClose, onNavigate }) {
  const status = useApi(`/api/bgp/connectors/${connector?.id}/status`, {
    enabled: Boolean(connector?.id),
    deps: [connector?.id],
  });
  const related = announcements.filter((item) => Number(item.connector_id) === Number(connector.id));
  const data = status.data ?? {};
  const verification = data.verification ?? {};
  const checks = data.checks ?? {};

  return (
    <div className="overlay" onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Conector ${connector.name}`}>
        <header>
          <div>
            <span className="eyebrow">BGP CONNECTOR</span>
            <h2>{connector.name}</h2>
            <p>{connector.peer_ip || '—'} · {connector.backend_type || '—'} · {connector.role || '—'}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fechar">×</button>
        </header>

        <section>
          <h4>1 · Identidade</h4>
          <KeyValues items={[
            ['id', `#${connector.id}`],
            ['nome', connector.name],
            ['role', <Badge tone={stateTone(connector.role)}>{connector.role || '—'}</Badge>],
            ['backend', connector.backend_type || '—'],
            ['modo', connector.mode || '—'],
            ['ativo', <Badge tone={connector.is_active ? 'success' : 'warning'}>{connector.is_active ? 'sim' : 'não'}</Badge>],
            ['habilitado', <Badge tone={connector.enabled ? 'success' : 'warning'}>{connector.enabled ? 'sim' : 'não'}</Badge>],
          ]} />
        </section>

        <section>
          <h4>2 · Configuração</h4>
          <KeyValues items={[
            ['ASN local', connector.local_asn ?? '—'],
            ['ASN peer', connector.peer_asn ?? '—'],
            ['peer IP', connector.peer_ip || '—'],
            ['local address', connector.local_address || '—'],
            ['router id', connector.router_id || '—'],
            ['next hop padrão', connector.default_next_hop || '—'],
            ['comunidade padrão', connector.default_community || '—'],
            ['large community', connector.default_large_community || '—'],
            ['máx. regras', connector.max_active_rules ?? '—'],
            ['TTL máx.', connector.max_duration_seconds != null ? `${connector.max_duration_seconds}s` : '—'],
            ['sensor', connector.sensor_id ?? '—'],
            ['notas', connector.notes || '—'],
          ]} />
        </section>

        <section>
          <h4>3 · Transport / listener</h4>
          <KeyValues items={[
            ['listen port', connector.listen_port ?? '—'],
            ['listener passivo', connector.passive_listen_enabled ? 'sim' : 'não'],
            ['pipe in', connector.exabgp_pipe_in || '—'],
            ['pipe out', connector.exabgp_pipe_out || '—'],
            ['config ExaBGP', connector.exabgp_config_path || '—'],
            ['serviço systemd', connector.systemd_service_name || '—'],
            ['check state', status.data?.check_state || '—'],
          ]} />
        </section>

        <section>
          <h4>4 · BGP FSM</h4>
          <KeyValues items={[
            ['bgp state', <Badge tone={stateTone(connector.bgp_state)}>{connector.bgp_state || '—'}</Badge>],
            ['verificado', verification.bgp_verified ? 'sim' : 'não'],
            ['peer state (snapshot)', data.bgp_state || '—'],
            ['última checagem', fmtTime(connector.last_checked_at)],
          ]} />
        </section>

        <section>
          <h4>5 · FlowSpec</h4>
          <KeyValues items={[
            ['flowspec state', <Badge tone={stateTone(connector.flowspec_state)}>{connector.flowspec_state || '—'}</Badge>],
            ['verificado', verification.flowspec_verified ? 'sim' : 'não'],
            ['habilitado no conector', data.flowspec_enabled ? 'sim' : 'não'],
            ['snapshot', data.flowspec_state || '—'],
          ]} />
        </section>

        <section>
          <h4>6 · FIFO / reader</h4>
          <KeyValues items={[
            ['pipe state', <Badge tone={stateTone(connector.pipe_state)}>{connector.pipe_state || '—'}</Badge>],
            ['verificado', verification.pipe_verified ? 'sim' : 'não'],
            ['pipes', shortJson(data.pipes)],
            ['reader ativo', data.reader_active ? 'sim' : (data.reader_active === false ? 'não' : '—')],
          ]} />
        </section>

        <section>
          <h4>7 · host-agent</h4>
          <KeyValues items={[
            ['router check habilitado', connector.router_check_enabled ? 'sim' : 'não'],
            ['verificação router', verification.router_check_enabled ? 'habilitada' : 'desabilitada'],
            ['host-agent', data.host_agent_reachable ? 'alcançável' : (data.host_agent_reachable === false ? 'não alcançável' : '—')],
            ['evidência', data.delivery_path_source || data.host_agent?.source || '—'],
          ]} />
        </section>

        <section>
          <h4>8 · Readiness</h4>
          <div className="chip-row">
            <ReadinessChip label="serviço" value={checks.service_ok ? 'ok' : '—'} ok={checks.service_ok} />
            <ReadinessChip label="listener" value={checks.listener_ok ? 'ok' : '—'} ok={checks.listener_ok} />
            <ReadinessChip label="pipe" value={checks.pipe_ok ? 'ok' : '—'} ok={checks.pipe_ok} />
            <ReadinessChip label="flow spec" value={checks.flowspec_ok ? 'ok' : '—'} ok={checks.flowspec_ok} />
            <ReadinessChip label="bgp" value={checks.bgp_ok ? 'ok' : '—'} ok={checks.bgp_ok} />
            <ReadinessChip label="transporte" value={checks.transport_ready ? 'ok' : '—'} ok={checks.transport_ready} />
            <ReadinessChip label="entrega" value={checks.delivery_path_ready ? 'ok' : '—'} ok={checks.delivery_path_ready} />
            <ReadinessChip label="peer" value={data.peer_state || (data.session_state ?? '—')} ok={String(data.peer_state || data.session_state || '').toLowerCase() === 'established'} />
          </div>
          {!Object.keys(checks).length ? (
            <p className="hint">O snapshot deste conector não trouxe o bloco de checks — a UI mostra apenas os estados persistidos.</p>
          ) : null}
        </section>

        <section>
          <h4>9 · Diagnóstico</h4>
          <KeyValues items={[
            ['mensagem', connector.status_message || data.message || '—'],
            ['erros', Array.isArray(connector.status_errors) && connector.status_errors.length ? connector.status_errors.join(' | ') : (data.errors?.length ? data.errors.join(' | ') : '—')],
            ['status snapshot', shortJson(connector.status_snapshot)],
          ]} />
        </section>

        <section>
          <h4>10 · Announcements relacionados</h4>
          {related.length ? (
            <Table
              columns={[
                { key: 'id', label: 'ID', render: (row) => <EntityLink label={`#${row.id}`} onClick={() => onNavigate('bgp', { kind: 'announcement', id: row.id })} /> },
                { key: 'target_prefix', label: 'Alvo', render: (row) => <code>{row.target_prefix || row.dst_prefix || '—'}</code> },
                { key: 'status', label: 'Status', render: (row) => <Badge tone={stateTone(row.status)}>{row.status || '—'}</Badge> },
                { key: 'confirmation_level', label: 'Confirmação', render: (row) => <span className="mono-small">{row.confirmation_level || '—'}</span> },
                { key: 'announced_at', label: 'Anunciado', render: (row) => fmtTime(row.announced_at || row.advertised_at) },
              ]}
              rows={related}
              keyFor={(row) => row.id}
              empty="Sem announcements."
            />
          ) : <EmptyState title="Nenhum announcement relacionado" hint="Nenhum registro em bgp_announcements usa este connector_id." />}
        </section>

        <footer>
          <ReadOnlyAction label="Checar router agora" reason="POST /api/bgp/connectors/{id}/check-router — bloqueado no preview" policy="A" />
          <ReadOnlyAction label="Recover sessions" reason="POST /api/bgp/connectors/recover-sessions — bloqueado no preview" policy="C" />
          <ReadOnlyAction label="Editar conector" reason="PUT /api/bgp/connectors/{id} — bloqueado no preview" policy="C" />
          <button type="button" className="control" onClick={onClose}>Fechar</button>
        </footer>
      </aside>
    </div>
  );
}

function AnnouncementDrawer({ announcement, executions, connectors, onClose, onNavigate }) {
  const detail = useApi(`/api/bgp/announcements/${announcement?.id}`, {
    enabled: Boolean(announcement?.id),
    deps: [announcement?.id],
  });
  const execution = executions.find((item) => (
    (announcement.source === 'automatic_orchestrator' && String(item.id) === String(announcement.source_id))
    || (announcement.mitigation_key && item.idempotency_key === announcement.mitigation_key)
  )) ?? null;
  /**
   * O vínculo execução↔announcement é provado pelo BACKEND via
   * `source = automatic_orchestrator` + `source_id`. Não dependemos de baixar a
   * lista pesada de execuções para oferecer o link: se o id vier no payload,
   * o link existe (a lista só melhora o rótulo).
   */
  const executionId = announcement.source === 'automatic_orchestrator' && announcement.source_id
    ? Number(announcement.source_id)
    : (execution?.id ?? null);
  const connector = connectors.find((item) => Number(item.id) === Number(announcement.connector_id)) ?? null;
  const events = Array.isArray(detail.data?.events) ? detail.data.events : [];
  const details = detail.data?.status_details ?? {};
  const checks = details.checks ?? {};

  return (
    <div className="overlay" onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Announcement ${announcement.id}`}>
        <header>
          <div>
            <span className="eyebrow">BGP ANNOUNCEMENT</span>
            <h2>Announcement #{announcement.id}</h2>
            <p>{announcement.target_prefix || announcement.dst_prefix || '—'} · {announcement.route_type || '—'}</p>
          </div>
          <button type="button" onClick={onClose} aria-label="Fechar">×</button>
        </header>

        <section>
          <h4>1 · Pedido</h4>
          <KeyValues items={[
            ['status', <Badge tone={stateTone(announcement.status)}>{announcement.status || '—'}</Badge>],
            ['anomalia', announcement.anomaly_id
              ? <EntityLink label={`#${announcement.anomaly_id}`} onClick={() => onNavigate('anomalies', { kind: 'anomaly', id: announcement.anomaly_id })} />
              : '—'],
            ['origem', announcement.source || '—'],
            ['source_id (execução)', announcement.source_id || '—'],
            ['mitigation key', <span className="mono-small">{announcement.mitigation_key || '—'}</span>],
            ['requested mode', announcement.requested_mode || '—'],
            ['criado', fmtTime(announcement.created_at)],
          ]} />
        </section>

        <section>
          <h4>2 · Policy / decisão</h4>
          <KeyValues items={[
            ['policy decision', <Badge tone={stateTone(announcement.policy_decision)}>{announcement.policy_decision || '—'}</Badge>],
            ['policy severity', <Badge tone={stateTone(announcement.policy_severity)}>{announcement.policy_severity || '—'}</Badge>],
            ['escopo exigido', announcement.policy_required_scope || '—'],
            ['port policies casadas', Array.isArray(announcement.policy_matched_port_policies) && announcement.policy_matched_port_policies.length
              ? announcement.policy_matched_port_policies.join(', ') : '—'],
            ['razões', Array.isArray(announcement.policy_reasons) && announcement.policy_reasons.length ? announcement.policy_reasons.join(' | ') : '—'],
            ['avisos', Array.isArray(announcement.policy_warnings) && announcement.policy_warnings.length ? announcement.policy_warnings.join(' | ') : '—'],
          ]} />
        </section>

        <section>
          <h4>3 · Comando</h4>
          <KeyValues items={[
            ['ação', <code>{announcement.action || '—'}</code>],
            ['response type', announcement.response_type || '—'],
            ['rate limit', announcement.rate_limit_bps ? `${fmtNumber(announcement.rate_limit_bps)} bps` : (announcement.rate_limit_value_raw || '—')],
            ['duração', announcement.duration_seconds != null ? `${announcement.duration_seconds}s` : '—'],
            ['profile', announcement.response_profile_name || (announcement.response_profile_id ? `#${announcement.response_profile_id}` : '—')],
            ['validation errors', Array.isArray(announcement.validation_errors) && announcement.validation_errors.length ? announcement.validation_errors.join(' | ') : '—'],
          ]} />
          <div className="command-block">
            <span>comando anunciado</span>
            <code>{announcement.announce_command || announcement.rendered_command || '—'}</code>
            <span>comando de retirada</span>
            <code>{announcement.withdraw_command || '—'}</code>
          </div>
        </section>

        <section>
          <h4>4 · Conector</h4>
          <KeyValues items={[
            ['conector', announcement.connector_id
              ? <EntityLink label={`#${announcement.connector_id}${connector ? ` · ${connector.name}` : ''}`} title="Abrir conector" onClick={() => onNavigate('bgp', { kind: 'connector', id: announcement.connector_id })} />
              : '—'],
            ['bgp state', connector ? <Badge tone={stateTone(connector.bgp_state)}>{connector.bgp_state || '—'}</Badge> : '—'],
            ['flowspec state', connector ? <Badge tone={stateTone(connector.flowspec_state)}>{connector.flowspec_state || '—'}</Badge> : '—'],
            ['pipe path', announcement.pipe_path || '—'],
          ]} />
        </section>

        <section>
          <h4>5 · ExaBGP / confirmação</h4>
          <div className="chip-row">
            {[
              ['serviço', checks.service_ok],
              ['listener', checks.listener_ok],
              ['pipe', checks.pipe_ok],
              ['flow spec', checks.flowspec_ok],
              ['bgp', checks.bgp_ok],
              ['entrega', checks.delivery_path_ready],
            ].map(([label, ok]) => (
              <ReadinessChip key={label} label={label} value={ok ? 'ok' : '—'} ok={ok} />
            ))}
          </div>
          <KeyValues items={[
            ['confirmation level', <Badge tone={stateTone(announcement.confirmation_level)}>{announcement.confirmation_level || '—'}</Badge>],
            ['peer state', <Badge tone={stateTone(announcement.peer_state)}>{announcement.peer_state || '—'}</Badge>],
            ['delivery path', details.delivery_path_reason || '—'],
            ['fonte da evidência', details.delivery_path_source || '—'],
            ['enviado em', fmtTime(announcement.sent_at || announcement.announced_at)],
            ['última tentativa', fmtTime(announcement.last_attempt_at)],
          ]} />
        </section>

        <section>
          <h4>6 · Expiração / retirada</h4>
          <KeyValues items={[
            ['expira em', fmtTime(announcement.expires_at)],
            ['retirado em', fmtTime(announcement.withdrawn_at)],
            ['aprovado em', fmtTime(announcement.approved_at)],
            ['rejeitado em', fmtTime(announcement.rejected_at)],
            ['último erro', announcement.last_error || '—'],
          ]} />
        </section>

        <section>
          <h4>7 · Níveis de evidência</h4>
          <div className="evidence-levels">
            <EvidenceLevel verified label="Pedido registrado" detail={`announcement #${announcement.id}`} />
            <EvidenceLevel verified={Boolean(announcement.policy_decision)} label="Policy decidiu" detail={`${announcement.policy_decision || '—'} / ${announcement.policy_severity || '—'}`} />
            <EvidenceLevel verified={Boolean(announcement.announce_command || announcement.rendered_command)} label="Comando gerado" detail="renderizado pelo backend" />
            <EvidenceLevel verified={Boolean(checks.delivery_path_ready)} label="Entregue ao ExaBGP" detail={details.delivery_path_reason || 'sem evidência de entrega'} />
            <EvidenceLevel verified={String(announcement.peer_state).toLowerCase() === 'established'} label="Peer BGP established" detail={announcement.peer_state || '—'} />
            <EvidenceLevel verified={false} label="Regra no RIB remoto" detail="sem endpoint que comprove" />
            <EvidenceLevel verified={false} label="Efeito no dataplane" detail="sem endpoint que comprove" />
          </div>
          {CONFIRMATION_ORDER.includes(announcement.confirmation_level) ? (
            <p className="hint">
              Confirmação registrada: <b>{announcement.confirmation_level}</b> — é o nível máximo que o sistema atual persiste.
            </p>
          ) : null}
        </section>

        <section>
          <h4>8 · Timeline (bgp_announcement_events)</h4>
          {detail.loading ? <Loading /> : detail.error ? <ErrorBox message={detail.error} /> : (
            <Timeline items={events.map((event) => ({
              title: `${event.event_type} · ${event.message || ''}`.trim(),
              at: fmtTime(event.created_at),
              detail: event.created_by ? `por ${event.created_by}` : null,
              tone: stateTone(event.event_type),
            }))} />
          )}
        </section>

        <section>
          <h4>9 · Links</h4>
          <div className="link-row">
            {executionId != null
              ? <EntityLink label={`Execução #${executionId}`} tone="success" onClick={() => onNavigate('mitigation', { kind: 'execution', id: executionId })} />
              : <span className="mono-small">execução não localizada (source_id / mitigation_key)</span>}
            {announcement.anomaly_id
              ? <EntityLink label={`Anomalia #${announcement.anomaly_id}`} onClick={() => onNavigate('anomalies', { kind: 'anomaly', id: announcement.anomaly_id })} />
              : null}
            {announcement.connector_id
              ? <EntityLink label={`Conector #${announcement.connector_id}`} onClick={() => onNavigate('bgp', { kind: 'connector', id: announcement.connector_id })} />
              : null}
          </div>
        </section>

        <footer>
          <ReadOnlyAction label="Aprovar" reason="POST /api/bgp/announcements/{id}/approve — bloqueado no preview" policy="C" />
          <ReadOnlyAction label="Rejeitar" reason="POST /api/bgp/announcements/{id}/reject — bloqueado no preview" policy="C" />
          <ReadOnlyAction label="Withdraw" reason="POST /api/bgp/announcements/{id}/withdraw — bloqueado no preview" policy="C" />
          <button type="button" className="control" onClick={onClose}>Fechar</button>
        </footer>
      </aside>
    </div>
  );
}

export default function Bgp({ focus, onNavigate }) {
  const [tab, setTab] = useState('OVERVIEW');
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');
  const [openConnectorId, setOpenConnectorId] = useState(null);
  const [openAnnouncementId, setOpenAnnouncementId] = useState(null);

  const summary = useApi('/api/bgp/summary');
  const connectors = useApi('/api/bgp/connectors?include_disabled=true');
  const announcements = useApi('/api/bgp/announcements?limit=500');
  const exabgp = useApi('/api/system/exabgp/status');
  const executions = useApi('/api/mitigation/executions?limit=400');
  const health = useApi('/api/mitigation/automation/health');

  const connectorList = connectors.data?.items ?? [];
  const announcementList = announcements.data?.items ?? [];
  const executionList = executions.data?.items ?? [];

  const focusConnectorId = focus?.kind === 'connector' ? focus.id : null;
  const focusAnnouncementId = focus?.kind === 'announcement' ? focus.id : null;
  const connector = (openConnectorId != null
    ? connectorList.find((item) => Number(item.id) === Number(openConnectorId))
    : null)
    ?? (focusConnectorId != null ? connectorList.find((item) => Number(item.id) === Number(focusConnectorId)) : null)
    ?? null;
  const announcement = (openAnnouncementId != null
    ? announcementList.find((item) => Number(item.id) === Number(openAnnouncementId))
    : null)
    ?? (focusAnnouncementId != null ? announcementList.find((item) => Number(item.id) === Number(focusAnnouncementId)) : null)
    ?? null;
  const closeConnector = () => {
    setOpenConnectorId(null);
    if (focusConnectorId != null) onNavigate('bgp', null);
  };
  const closeAnnouncement = () => {
    setOpenAnnouncementId(null);
    if (focusAnnouncementId != null) onNavigate('bgp', null);
  };
  /**
   * Cross-link dentro da própria página (conector ↔ announcement): os dois
   * drawers nunca podem ficar montados ao mesmo tempo — abrir um fecha o outro.
   */
  useEffect(() => {
    if (focus?.kind === 'announcement') setOpenConnectorId(null);
    if (focus?.kind === 'connector') setOpenAnnouncementId(null);
  }, [focus]);

  const established = connectorList.filter((item) => String(item.bgp_state).toLowerCase() === 'established').length;
  const unverified = connectorList.filter((item) => ['not_checked', '', null, undefined].includes(item.bgp_state)).length;
  const down = connectorList.length - established - unverified;
  const flowspecReady = connectorList.filter((item) => String(item.flowspec_state).toLowerCase() === 'established').length;
  const pipeOk = connectorList.filter((item) => String(item.pipe_state).toLowerCase() === 'ok').length;
  const advertised = announcementList.filter((item) => item.status === 'advertised');
  const pending = announcementList.filter((item) => ['queued', 'sent', 'pending_approval', 'prepared'].includes(item.status));
  const failed = announcementList.filter((item) => ['failed', 'failed_withdraw', 'peer_down', 'rejected', 'rejected_by_policy'].includes(item.status));
  const expired = announcementList.filter((item) => item.status === 'expired');

  const filteredAnnouncements = useMemo(() => {
    const term = search.trim().toLowerCase();
    return announcementList.filter((item) => {
      if (statusFilter && item.status !== statusFilter) return false;
      if (!term) return true;
      return String(item.id).includes(term)
        || String(item.anomaly_id ?? '').includes(term)
        || String(item.target_prefix ?? item.dst_prefix ?? '').toLowerCase().includes(term)
        || String(item.connector_name ?? item.connector_id ?? '').toLowerCase().includes(term);
    });
  }, [announcementList, search, statusFilter]);

  const pipes = exabgp.data?.pipes ?? {};

  return (
    <div className="main-content">
      <div className="page-head">
        <div>
          <h2>BGP / Conectores</h2>
          <p>Readiness por camada, conectores, announcements e evidência de entrega — dados reais, somente leitura</p>
        </div>
        <div className="page-head-actions">
          <Badge tone={established === connectorList.length && connectorList.length > 0 ? 'success' : 'warning'}>
            <StatusDot tone={established === connectorList.length && connectorList.length > 0 ? 'success' : 'warning'} />
            {established}/{connectorList.length} established
          </Badge>
          <ReadOnlyAction label="Recover sessions" reason="POST /api/bgp/connectors/recover-sessions — bloqueado no preview" policy="C" />
        </div>
      </div>

      <Tabs
        value={tab}
        onChange={setTab}
        tabs={[
          ['OVERVIEW', 'Overview', connectorList.length],
          ['CONECTORES', 'Conectores', connectorList.length],
          ['ANNOUNCEMENTS', 'Announcements', announcementList.length],
        ]}
      />

      {tab === 'OVERVIEW' ? (
        <>
          <Panel title="Readiness" subtitle="cada camada separada — nada é agregado num único ONLINE" badge={exabgp.error ? 'Indisponível' : 'ao vivo'} badgeTone={exabgp.error ? 'warning' : 'success'}>
            {exabgp.loading ? <Loading /> : exabgp.error ? <ErrorBox message={exabgp.error} /> : (
              <div className="chip-row" style={{ padding: '10px 12px 4px' }}>
                <ReadinessChip label="exabgp instalado" value={exabgp.data?.installed ? 'sim' : 'não'} ok={Boolean(exabgp.data?.installed)} />
                <ReadinessChip label="serviço" value={exabgp.data?.service?.active ? 'active' : (exabgp.data?.service?.state || '—')} ok={Boolean(exabgp.data?.service?.active)} hint={exabgp.data?.service?.message} />
                <ReadinessChip label="listener" value={exabgp.data?.tcp_179_listening ? 'TCP/179' : 'sem listener'} ok={Boolean(exabgp.data?.tcp_179_listening)} />
                <ReadinessChip label="fifo in" value={pipes.backend_or_host_in_exists ? 'existe' : '—'} ok={Boolean(pipes.backend_or_host_in_exists)} />
                <ReadinessChip label="fifo out" value={pipes.backend_or_host_out_exists ? 'existe' : '—'} ok={Boolean(pipes.backend_or_host_out_exists)} />
                <ReadinessChip label="mount backend" value={pipes.backend_mount_visible ? 'visível' : 'não'} ok={Boolean(pipes.backend_mount_visible)} />
                <ReadinessChip label="bgp fsm" value={`${established}/${connectorList.length}`} ok={established === connectorList.length && connectorList.length > 0} />
                <ReadinessChip label="flow spec" value={`${flowspecReady}/${connectorList.length}`} ok={flowspecReady === connectorList.length && connectorList.length > 0} />
                <ReadinessChip label="pipe" value={`${pipeOk}/${connectorList.length}`} ok={pipeOk === connectorList.length && connectorList.length > 0} />
                <ReadinessChip label="reader / fifo" value={`${pipeOk > 0 ? pipeOk : 0} pipes`} ok={pipeOk > 0} hint={pipes.path} />
                <ReadinessChip label="host-agent" value={pipes.message ? 'com pendência' : '—'} ok={null} hint={pipes.message} />
              </div>
            )}
            {exabgp.data?.config_paths ? (
              <div className="kv-grid">
                {exabgp.data.config_paths.map((path) => <div key={path}><span>config</span><b className="mono-small">{path}</b></div>)}
              </div>
            ) : null}
          </Panel>

          <section className="metrics-grid wide">
            <Kpi label="Conectores" value={fmtNumber(connectorList.length)} hint="bgp_connectors" tone="rail-info" />
            <Kpi label="Established" value={fmtNumber(established)} tone={established === connectorList.length ? 'rail-success' : 'rail-warning'} />
            <Kpi label="Não verificados" value={fmtNumber(unverified)} hint="bgp_state sem valor" />
            <Kpi label="Down" value={fmtNumber(down)} tone={down ? 'rail-critical' : 'rail-success'} hint="nem established nem não verificado" />
            <Kpi label="FlowSpec ready" value={`${flowspecReady}/${connectorList.length}`} tone="rail-info" />
            <Kpi label="Anúncios ativos" value={fmtNumber(advertised.length)} hint="status advertised" tone="rail-success" />
            <Kpi label="Pendentes" value={fmtNumber(pending.length)} tone="rail-warning" />
            <Kpi label="Falhas / rejeitados" value={fmtNumber(failed.length)} tone={failed.length ? 'rail-critical' : 'rail-success'} />
            <Kpi label="Expirados" value={fmtNumber(expired.length)} hint="TTL encerrado" />
            <Kpi label="Freshness" value={summary.data?.active_bgp_announcements != null ? `${fmtNumber(summary.data.active_bgp_announcements)} ativos` : '—'} hint="bgp/summary" tone="rail-info" />
          </section>

          <div className="two-columns">
            <Panel title="Resumo BGP (backend)" subtitle="/api/bgp/summary" badge="agregado real">
              {summary.loading ? <Loading /> : summary.error ? <ErrorBox message={summary.error} /> : (
                <div className="kv-grid">
                  {Object.entries(summary.data ?? {}).map(([key, value]) => (
                    <div key={key}><span>{key}</span><b>{typeof value === 'number' ? fmtNumber(value) : String(value ?? '—')}</b></div>
                  ))}
                </div>
              )}
            </Panel>

            <Panel title="Automação de mitigação" subtitle="contexto do orquestrador que anuncia" badge={health.data?.worker_enabled ? 'habilitado' : 'desabilitado'} badgeTone={health.data?.worker_enabled ? 'success' : 'warning'}>
              {health.loading ? <Loading /> : health.error ? <ErrorBox message={health.error} /> : (
                <div className="kv-grid">
                  <div><span>thread</span><b>{health.data?.thread_alive ? 'ativa' : 'parada'}</b></div>
                  <div><span>worker</span><b>{health.data?.worker_enabled ? 'habilitado' : 'desabilitado'}</b></div>
                  <div><span>intervalo</span><b>{health.data?.interval_seconds ?? '—'}s</b></div>
                  <div><span>último job</span><b>{fmtTime(health.data?.last_job_at)}</b></div>
                  <div><span>última execução</span><b>{fmtTime(health.data?.last_execution_at)}</b></div>
                  <div><span>total</span><b>{fmtNumber(health.data?.total ?? 0)}</b></div>
                </div>
              )}
            </Panel>
          </div>
        </>
      ) : null}

      {tab === 'CONECTORES' ? (
        <Panel title="Conectores" subtitle="bgp_state · flowspec_state · pipe_state · última checagem" badge={connectorList.length}>
          {connectors.loading ? <Loading /> : connectors.error ? <ErrorBox message={connectors.error} /> : (
            <Table
              onRowClick={(row) => { setOpenAnnouncementId(null); setOpenConnectorId(row.id); }}
              columns={[
                { key: 'name', label: 'Conector' },
                { key: 'peer_ip', label: 'Peer', render: (row) => <code>{row.peer_ip || '—'}</code> },
                { key: 'local_address', label: 'Local', render: (row) => <code>{row.local_address || '—'}</code> },
                { key: 'asn', label: 'ASN', render: (row) => <span className="mono-small">{row.local_asn ?? '—'} → {row.peer_asn ?? '—'}</span> },
                { key: 'bgp_state', label: 'BGP FSM', render: (row) => <Badge tone={stateTone(row.bgp_state)}>{row.bgp_state || '—'}</Badge> },
                { key: 'flowspec_state', label: 'FlowSpec', render: (row) => <Badge tone={stateTone(row.flowspec_state)}>{row.flowspec_state || '—'}</Badge> },
                { key: 'pipe_state', label: 'Pipe', render: (row) => <Badge tone={stateTone(row.pipe_state)}>{row.pipe_state || '—'}</Badge> },
                { key: 'listener', label: 'Listener', render: (row) => (row.passive_listen_enabled ? `passivo ${row.listen_port ?? ''}` : `porta ${row.listen_port ?? '—'}`) },
                { key: 'last_checked_at', label: 'Última checagem', render: (row) => fmtTime(row.last_checked_at) },
                { key: 'enabled', label: 'Ativo', render: (row) => <Badge tone={row.enabled ? 'success' : 'warning'}>{row.enabled ? 'sim' : 'não'}</Badge> },
              ]}
              rows={connectorList}
              keyFor={(row) => row.id}
              empty="Nenhum conector cadastrado."
            />
          )}
        </Panel>
      ) : null}

      {tab === 'ANNOUNCEMENTS' ? (
        <Panel
          title="Announcements"
          subtitle="bgp_announcements — confirmação registrada por nível, sem promover evidência"
          badge={`${filteredAnnouncements.length}/${announcementList.length}`}
          filters={(
            <div className="filter-row">
              <label>
                Status
                <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                  <option value="">Todos os status</option>
                  {ANNOUNCEMENT_STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
              </label>
              <label>
                Buscar
                <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="id, anomalia, prefixo, conector" />
              </label>
            </div>
          )}
        >
          {announcements.loading ? <Loading /> : announcements.error ? <ErrorBox message={announcements.error} /> : (
            <Table
              onRowClick={(row) => { setOpenConnectorId(null); setOpenAnnouncementId(row.id); }}
              columns={[
                { key: 'id', label: 'ID' },
                { key: 'target_prefix', label: 'Alvo', render: (row) => <code>{row.target_prefix || row.dst_prefix || '—'}</code> },
                { key: 'route_type', label: 'Route' },
                { key: 'connector', label: 'Conector', render: (row) => row.connector_name || (row.connector_id ? `#${row.connector_id}` : '—') },
                { key: 'anomaly_id', label: 'Anomalia', render: (row) => row.anomaly_id != null ? `#${row.anomaly_id}` : '—' },
                { key: 'source', label: 'Origem', render: (row) => <span className="mono-small">{row.source || '—'} / {row.source_id || '—'}</span> },
                { key: 'status', label: 'Status', render: (row) => <Badge tone={stateTone(row.status)}>{row.status || '—'}</Badge> },
                { key: 'policy_decision', label: 'Policy', render: (row) => <span className="mono-small">{row.policy_decision || '—'} / {row.policy_severity || '—'}</span> },
                { key: 'confirmation_level', label: 'Confirmação', render: (row) => <Badge tone={stateTone(row.confirmation_level)}>{row.confirmation_level || '—'}</Badge> },
                { key: 'advertised_at', label: 'Anunciado', render: (row) => fmtTime(row.announced_at || row.advertised_at) },
                { key: 'expires_at', label: 'Expira', render: (row) => fmtTime(row.expires_at) },
                { key: 'withdrawn_at', label: 'Retirado', render: (row) => fmtTime(row.withdrawn_at) },
              ]}
              rows={filteredAnnouncements}
              keyFor={(row) => row.id}
              empty="Nenhum announcement para o filtro atual."
            />
          )}
        </Panel>
      ) : null}

      {connector ? (
        <ConnectorDrawer
          connector={connector}
          announcements={announcementList}
          onClose={closeConnector}
          onNavigate={onNavigate}
        />
      ) : null}

      {announcement ? (
        <AnnouncementDrawer
          announcement={announcement}
          executions={executionList}
          connectors={connectorList}
          onClose={closeAnnouncement}
          onNavigate={onNavigate}
        />
      ) : null}
    </div>
  );
}
