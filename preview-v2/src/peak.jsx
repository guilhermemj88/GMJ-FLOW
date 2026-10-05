import React, { useMemo, useState } from 'react';
import {
  Badge, EmptyState, EntityLink, ErrorBox, Loading, Panel, ReadOnlyAction,
  Table, fmtNumber, fmtTime, useApi,
} from './shared.jsx';

/**
 * BLOCO 2 - Peak Hunter (PREVIEW V2, somente leitura).
 *
 * Endpoints REAIS auditados (todos GET):
 *   /api/peak-hunter/options/sensors  -  /options/interfaces
 *   /api/peak-hunter/events  -  /events/{id}
 *   /api/peak-hunter/history  -  /history/{id}
 *   /api/peak-hunter/automation/jobs  -  /automation/status  -  /automation/runs
 *   /api/peak-hunter/export-dataset (download)
 *
 * POSTs reais (/analyze, /simple/analyze, drafts, feedback, run-now) NAO sao
 * executados: a preview e read-only e o proxy bloqueia escrita (405).
 */

const TABS = [
  ['peaks', 'Picos persistidos'],
  ['history', 'Historico de analises'],
  ['automation', 'Automacao'],
  ['scope', 'Sensores & interfaces'],
];

function Dash() {
  return <span className="v2-dash">-</span>;
}

function value(v) {
  return v === null || v === undefined || v === '' ? <Dash /> : v;
}

function DirectionBadge({ direction }) {
  const key = String(direction || '').toLowerCase();
  if (key === 'sends') return <Badge tone="warning">sends</Badge>;
  if (key === 'receives') return <Badge tone="info">receives</Badge>;
  return <Badge tone="muted">{direction || '-'}</Badge>;
}

function Cells({ entries }) {
  return (
    <div className="v2-cells">
      {entries.map(([label, val], index) => (
        <div key={`${label}-${index}`}><span>{label}</span><b>{value(val)}</b></div>
      ))}
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section className="v2-section">
      <h4>{title}</h4>
      {children}
    </section>
  );
}

function PeakDrawer({ id, onClose }) {
  const detail = useApi(`/api/peak-hunter/history/${id}`);
  const item = detail.data || {};
  const candidates = Array.isArray(item.candidates)
    ? item.candidates
    : (Array.isArray(item.candidates_json) ? item.candidates_json : []);
  const evidence = item.evidence || (item.result ? item.result.evidence : null) || {};
  const threat = item.threat || (item.result ? item.result.threat : null) || {};
  return (
    <div className="v2-drawer-overlay" onClick={onClose}>
      <aside className="v2-drawer" onClick={(event) => event.stopPropagation()}>
        <header className="v2-drawer-head">
          <div><h3>Analise #{id}</h3><p>Peak Hunter - historico persistido</p></div>
          <button className="control" onClick={onClose}>Fechar</button>
        </header>
        <div className="v2-drawer-body">
          <div className="v2-readonly-note">
            <Badge tone="critical">SOMENTE LEITURA</Badge>
            <span>Feedback, draft e run-now sao POST e permanecem bloqueados.</span>
          </div>
          {detail.error ? <ErrorBox message={detail.error} /> : null}
          {detail.loading ? <Loading /> : (
            <>
              <Section title="1 - Escopo e janela">
                <Cells entries={[
                  ['Sensor', item.sensor],
                  ['Interface', item.interface_id],
                  ['Direcao', item.direction],
                  ['Metrica', item.metric],
                  ['Protocolo', item.protocol],
                  ['Pico (UTC)', item.peak_time_utc ? fmtTime(item.peak_time_utc) : ''],
                  ['Pico (local)', item.peak_time_local ? fmtTime(item.peak_time_local) : ''],
                  ['Threshold usado', item.threshold_used != null ? fmtNumber(item.threshold_used) : ''],
                ]} />
              </Section>
              <Section title="2 - Evidencia do pico">
                <Cells entries={[
                  ['Status da evidencia', item.evidence_status || evidence.evidence_status],
                  ['Classificacao', item.classification],
                  ['Grupo dominante', item.dominant_group],
                  ['Share de pacotes', item.dominant_share_packets != null ? `${fmtNumber(item.dominant_share_packets * 100, 1)}%` : ''],
                  ['Destino dominante', item.dominant_dst_ip],
                  ['Porta destino dominante', item.dominant_dst_port],
                  ['Origens distintas (grupo dominante)', item.dominant_unique_src_count],
                  ['Mitigacao permitida', item.mitigation_allowed ? 'sim (fora da preview)' : 'nao'],
                ]} />
              </Section>
              <Section title="3 - Candidatos e triagem">
                <Table
                  columns={[
                    { key: 'name', label: 'Candidato', render: (r) => r.name || r.label || r.attack_vector_name || '-' },
                    { key: 'score', label: 'Score', render: (r) => fmtNumber(r.score, 2) },
                    { key: 'reason', label: 'Motivo' },
                  ]}
                  rows={candidates}
                  keyFor={(r, i) => r.id || `${r.name}-${i}`}
                  empty="Sem candidatos registrados nesta analise."
                />
                <div className="v2-note" style={{ marginTop: 8 }}>
                  Veredito de ameaca: {threat.verdict || item.threat_verdict || '-'}
                  {Array.isArray(threat.reasons) && threat.reasons.length ? ` - ${threat.reasons.join(' - ')}` : ''}
                </div>
              </Section>
              <Section title="4 - Leitura do operador (historico)">
                <Cells entries={[
                  ['Rotulo', item.operator_label],
                  ['Vetor confirmado', item.operator_vector],
                  ['Melhor acao', item.operator_best_action],
                  ['Template confirmado', item.operator_confirmed_template],
                  ['TTL confirmado', item.operator_confirmed_ttl],
                  ['Comentario', item.operator_comment],
                  ['Resolvido por mitigacao', item.resolved_by_mitigation ? 'sim' : 'nao'],
                  ['Feedback atualizado', item.feedback_updated_at ? fmtTime(item.feedback_updated_at) : ''],
                ]} />
                <div style={{ marginTop: 8 }}>
                  <ReadOnlyAction label="Registrar feedback operacional" reason="PATCH /api/peak-hunter/history/{id}/feedback e escrita - bloqueado no proxy." policy="A" />
                </div>
              </Section>
              <Section title="5 - Handoff para engenharia de deteccao">
                <div className="v2-note">
                  Drafts reais existem no backend (detection rule, attack vector, response profile,
                  playbook), mas sao POST. Nesta fase apenas a leitura e exposta - veja a pagina
                  Vetores de Ataque para o estado atual das regras.
                </div>
                <div style={{ marginTop: 8 }}>
                  <ReadOnlyAction label="Criar detection rule draft" reason="POST - somente leitura nesta fase." policy="B" />
                  <ReadOnlyAction label="Criar attack vector draft" reason="POST - somente leitura nesta fase." policy="B" />
                </div>
              </Section>
            </>
          )}
        </div>
      </aside>
    </div>
  );
}

export default function Peak() {
  const [tab, setTab] = useState('peaks');
  const [historyId, setHistoryId] = useState(null);
  const events = useApi('/api/peak-hunter/events?limit=100');
  const history = useApi('/api/peak-hunter/history?limit=200');
  const sensors = useApi('/api/peak-hunter/options/sensors');
  const interfaces = useApi('/api/peak-hunter/options/interfaces?limit=400');
  const jobs = useApi('/api/peak-hunter/automation/jobs');
  const status = useApi('/api/peak-hunter/automation/status');
  const runs = useApi('/api/peak-hunter/automation/runs?limit=100');

  const eventRows = events.data?.items || [];
  const historyRows = history.data?.items || [];
  const sensorRows = sensors.data?.items || [];
  const interfaceRows = interfaces.data?.items || [];
  const jobRows = jobs.data?.items || [];
  const runRows = runs.data?.items || [];
  const statusData = status.data || {};
  const jobsEnabled = useMemo(() => jobRows.filter((job) => job.enabled).length, [jobRows]);

  return (
    <div className="page">
      <div className="v2-tabs">
        {TABS.map(([id, label]) => (
          <button key={id} className={tab === id ? 'v2-tab on' : 'v2-tab'} onClick={() => setTab(id)}>{label}</button>
        ))}
        <span className="v2-tab-spacer" />
        <Badge tone="info">{eventRows.length} eventos</Badge>
        <Badge tone="muted">{historyRows.length} analises</Badge>
      </div>

      <div className="v2-readonly-note">
        <Badge tone="critical">SOMENTE LEITURA</Badge>
        <span>Execucao manual (POST /api/peak-hunter/analyze e /simple/analyze), feedback e run-now de automacao nao sao executados pela preview.</span>
      </div>

      {tab === 'peaks' ? (
        <Panel title="Picos persistidos" subtitle="Saida do runner automatico (peak_events)" badge={eventRows.length} badgeTone={events.error ? 'warning' : 'info'}>
          {events.error ? <ErrorBox message={events.error} /> : null}
          {events.loading ? <Loading /> : (
            <Table
              columns={[
                { key: 'detected_at', label: 'Detectado', render: (r) => fmtTime(r.detected_at) },
                { key: 'sensor', label: 'Sensor' },
                { key: 'interface_id', label: 'Interface' },
                { key: 'direction', label: 'Direcao', render: (r) => <DirectionBadge direction={r.direction} /> },
                { key: 'trigger', label: 'Trigger' },
                { key: 'peak_pps', label: 'Pico pps', render: (r) => fmtNumber(r.peak_pps) },
                { key: 'peak_bps', label: 'Pico bits/s', render: (r) => fmtNumber(r.peak_bps) },
                { key: 'threat_verdict', label: 'Veredito' },
                { key: 'anomaly_id', label: 'Anomalia' },
              ]}
              rows={eventRows}
              keyFor={(r) => r.id}
              empty={<EmptyState title="Nenhum peak persistido" hint="O runner automatico esta habilitado, mas nao ha picos salvos na base real." />}
            />
          )}
        </Panel>
      ) : null}

      {tab === 'history' ? (
        <Panel title="Historico de analises" subtitle="peak_analysis - abra para ver evidencia, candidatos e leitura do operador" badge={historyRows.length} badgeTone={history.error ? 'warning' : 'info'}>
          {history.error ? <ErrorBox message={history.error} /> : null}
          {history.loading ? <Loading /> : (
            <Table
              columns={[
                { key: 'peak_time_utc', label: 'Pico (UTC)', render: (r) => fmtTime(r.peak_time_utc || r.peak_time) },
                { key: 'sensor', label: 'Sensor' },
                { key: 'interface_id', label: 'Interface' },
                { key: 'direction', label: 'Direcao', render: (r) => <DirectionBadge direction={r.direction} /> },
                { key: 'metric', label: 'Metrica' },
                { key: 'peak_value', label: 'Pico', render: (r) => fmtNumber(r.peak_value) },
                { key: 'score', label: 'Score', render: (r) => fmtNumber(r.score, 2) },
                { key: 'evidence_status', label: 'Evidencia' },
                { key: 'classification', label: 'Classificacao' },
                { key: 'abrir', label: '', render: (r) => <EntityLink label="investigar" onClick={() => setHistoryId(r.id)} tone="info" /> },
              ]}
              rows={historyRows}
              keyFor={(r) => r.id}
              empty={<EmptyState title="Nenhuma analise registrada" hint="Analises manuais/automaticas aparecem aqui quando existirem na base real." />}
            />
          )}
        </Panel>
      ) : null}

      {tab === 'automation' ? (
        <>
          <Panel title="Automacao - status do runner" subtitle="peak_hunter_automation_status" badge={statusData.scheduler_running ? 'executando' : 'parado'} badgeTone={statusData.scheduler_running ? 'ok' : 'muted'}>
            {status.error ? <ErrorBox message={status.error} /> : null}
            {status.loading ? <Loading /> : (
              <Cells entries={[
                ['Scheduler', statusData.scheduler_status],
                ['Ultimo tick', statusData.last_tick_at ? fmtTime(statusData.last_tick_at) : ''],
                ['Proximo tick (s)', statusData.next_tick_in_seconds],
                ['Jobs habilitados', `${jobsEnabled} de ${jobRows.length}`],
                ['Jobs devidos', statusData.jobs_due],
                ['Casos salvos', statusData.cases_saved],
                ['Amostras negativas', statusData.negative_samples_saved],
                ['Duplicados ignorados', statusData.duplicates_ignored],
                ['Ultimo erro', statusData.last_error],
              ]} />
            )}
          </Panel>
          <Panel title="Jobs" subtitle="Automacao real (leitura)" badge={jobRows.length} badgeTone={jobs.error ? 'warning' : 'info'}>
            {jobs.error ? <ErrorBox message={jobs.error} /> : null}
            {jobs.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'name', label: 'Job' },
                  { key: 'enabled', label: 'Habilitado', render: (r) => <Badge tone={r.enabled ? 'ok' : 'muted'}>{r.enabled ? 'sim' : 'nao'}</Badge> },
                  { key: 'sensor', label: 'Sensor' },
                  { key: 'direction', label: 'Direcao' },
                  { key: 'metric', label: 'Metrica' },
                  { key: 'interval_minutes', label: 'Intervalo (min)' },
                  { key: 'lookback_minutes', label: 'Lookback (min)' },
                  { key: 'min_peak_score', label: 'Score min.', render: (r) => fmtNumber(r.min_peak_score, 1) },
                  { key: 'runs_count', label: 'Execucoes' },
                  { key: 'last_run_at', label: 'Ultima', render: (r) => (r.last_run_at ? fmtTime(r.last_run_at) : 'nunca') },
                ]}
                rows={jobRows}
                keyFor={(r) => r.id}
                empty="Nenhum job configurado."
              />
            )}
            <div style={{ marginTop: 8 }}>
              <ReadOnlyAction label="Executar job agora" reason="POST /api/peak-hunter/automation/jobs/{id}/run-now grava execucao - bloqueado." policy="A" />
            </div>
          </Panel>
          <Panel title="Execucoes do runner" subtitle="peak_hunter_job_runs" badge={runRows.length} badgeTone={runs.error ? 'warning' : 'info'}>
            {runs.error ? <ErrorBox message={runs.error} /> : null}
            {runs.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'id', label: 'Run' },
                  { key: 'job_id', label: 'Job' },
                  { key: 'started_at', label: 'Inicio', render: (r) => fmtTime(r.started_at) },
                  { key: 'status', label: 'Status' },
                  { key: 'peaks_found', label: 'Picos' },
                  { key: 'cases_saved', label: 'Casos salvos' },
                  { key: 'error', label: 'Erro' },
                ]}
                rows={runRows}
                keyFor={(r) => r.id}
                empty="Sem execucoes registradas."
              />
            )}
          </Panel>
        </>
      ) : null}

      {tab === 'scope' ? (
        <>
          <Panel title="Sensores disponiveis" subtitle="Options reais do Peak Hunter" badge={sensorRows.length} badgeTone={sensors.error ? 'warning' : 'info'}>
            {sensors.error ? <ErrorBox message={sensors.error} /> : null}
            {sensors.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'sensor_id', label: 'ID' },
                  { key: 'sensor_name', label: 'Sensor' },
                  { key: 'exporter_ip', label: 'Exporter' },
                  { key: 'last_seen', label: 'Visto em', render: (r) => fmtTime(r.last_seen) },
                  { key: 'status', label: 'Status' },
                  { key: 'row_count', label: 'Registros', render: (r) => fmtNumber(r.row_count) },
                ]}
                rows={sensorRows}
                keyFor={(r) => r.sensor_id}
                empty="Nenhum sensor retornado."
              />
            )}
          </Panel>
          <Panel title="Interfaces" subtitle="Options reais (ifIndex por sensor)" badge={interfaceRows.length} badgeTone={interfaces.error ? 'warning' : 'info'}>
            {interfaces.error ? <ErrorBox message={interfaces.error} /> : null}
            {interfaces.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'interface_id', label: 'ifIndex' },
                  { key: 'ifName', label: 'Nome' },
                  { key: 'ifAlias', label: 'Alias' },
                  { key: 'direction_hints', label: 'Direcao sugerida' },
                  { key: 'last_seen', label: 'Visto em', render: (r) => fmtTime(r.last_seen) },
                  { key: 'label', label: 'Rotulo' },
                ]}
                rows={interfaceRows.slice(0, 400)}
                keyFor={(r) => `${r.interface_id}-${r.label}`}
                empty="Nenhuma interface retornada."
              />
            )}
          </Panel>
        </>
      ) : null}

      <Panel title="Dataset de analises (export)" subtitle="GET real - download do dataset JSONL do Peak Hunter" badge="jsonl" badgeTone="info">
        <div className="v2-note">
          A exportacao e GET (/api/peak-hunter/export-dataset) e por isso atravessa o proxy
          read-only. Ela exige sessao autenticada; nenhum parametro e alterado pela preview.
        </div>
      </Panel>

      {historyId ? <PeakDrawer id={historyId} onClose={() => setHistoryId(null)} /> : null}
    </div>
  );
}
