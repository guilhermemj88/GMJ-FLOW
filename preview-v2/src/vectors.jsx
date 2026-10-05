import React, { useMemo, useState } from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Panel, ReadOnlyAction,
  Table, fmtNumber, fmtTime, useApi,
} from './shared.jsx';

/**
 * BLOCO 2 - Vetores de Ataque / Detection Engineering (PREVIEW V2, read-only).
 *
 * Endpoints REAIS auditados (todos GET):
 *   /api/attack-vectors                       16 vetores
 *   /api/attack-vectors/templates             6 presets embutidos
 *   /api/attack-vector-templates              1 template em banco (THRESHOLD-PADRAO)
 *   /api/attack-vector-suggestions            sugestoes de aprendizado
 *   /api/detection/status                     scheduler das regras
 *   /api/detection/templates                  templates de deteccao (2)
 *   /api/detection/templates/{id}/rules       28 regras
 *   /api/detection/whitelist
 *
 * O HAVING real de cada detector e mostrado explicitamente: nos vetores inbound a
 * cardinalidade NAO participa do trigger; no vetor de upload many-clients ela E
 * condicao. A UI nao mistura "por que disparou" com "forma do trafego".
 */

const TABS = [
  ['vectors', 'Vetores'],
  ['rules', 'Regras de deteccao'],
  ['templates', 'Templates'],
  ['whitelist', 'Whitelist'],
  ['suggestions', 'Sugestoes'],
];

function value(v) {
  return v === null || v === undefined || v === '' ? '-' : v;
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

function DirectionBadge({ direction }) {
  const key = String(direction || '').toLowerCase();
  if (key === 'sends' || key === 'transmits') return <Badge tone="warning">{direction}</Badge>;
  if (key === 'receives') return <Badge tone="info">{direction}</Badge>;
  return <Badge tone="muted">{direction || '-'}</Badge>;
}

function SeverityBadge({ severity }) {
  const key = String(severity || '').toLowerCase();
  if (key === 'critical') return <Badge tone="critical">critical</Badge>;
  if (key === 'warning') return <Badge tone="warning">warning</Badge>;
  return <Badge tone="muted">{severity || '-'}</Badge>;
}

/** HAVING real do detector UDP, por vetor (auditado no backend). */
function havingFor(name) {
  const key = String(name || '').toUpperCase();
  if (key === 'UDP_UPLOAD_MANY_CLIENTS_SAME_DST_PORT' || key === 'UDP_MANY_INTERNAL_TO_SAME_DST_PORT') {
    return 'packets_s >= threshold AND unique_src_ips >= threshold AND unique_dst_ips = 1 AND unique_dst_ports = 1';
  }
  if (key === 'UDP_UPLOAD_SINGLE_CLIENT_HIGH_PPS') return 'packets_s >= threshold';
  if (key === 'UDP_DOWNLOAD_REFLECTION_TO_CLIENT' || key === 'UDP_DOWNLOAD_SAME_DST_PORT_TO_CLIENT') {
    return 'packets_s >= threshold (cardinalidade NAO participa)';
  }
  return '';
}

function RowDrawer({ kind, row, onClose }) {
  const item = row || {};
  return (
    <div className="v2-drawer-overlay" onClick={onClose}>
      <aside className="v2-drawer" onClick={(event) => event.stopPropagation()}>
        <header className="v2-drawer-head">
          <div>
            <h3>{kind === 'rule' ? `Regra #${item.id}` : `Vetor #${item.id}`}</h3>
            <p>{item.display_name || item.vector || item.name || '-'}</p>
          </div>
          <button className="control" onClick={onClose}>Fechar</button>
        </header>
        <div className="v2-drawer-body">
          <div className="v2-readonly-note">
            <Badge tone="critical">SOMENTE LEITURA</Badge>
            <span>Editar, duplicar, testar e aplicar sugestao sao POST/PUT/DELETE - bloqueados no proxy (405).</span>
          </div>
          <Section title="1 - Identificacao">
            <Cells entries={[
              ['ID', item.id],
              ['Nome tecnico', kind === 'rule' ? item.vector : item.name],
              ['Nome de exibicao', item.display_name],
              ['Habilitado', item.enabled === false ? 'nao' : 'sim'],
              ['Template', item.template_name],
              ['Dominio', item.domain_type || item.domain],
            ]} />
          </Section>
          <Section title="2 - Condicao real do detector">
            <Cells entries={[
              ['Direcao', item.direction],
              ['Protocolo', item.protocol],
              ['Metrica / unidade', item.threshold_unit || item.metric],
              ['Comparacao', item.comparison],
              ['Threshold', kind === 'rule'
                ? `warn ${fmtNumber(item.warning_value)} / crit ${fmtNumber(item.critical_value)}`
                : fmtNumber(item.threshold_value)],
              ['Janela (s)', item.window_seconds],
              ['Janelas consecutivas', item.consecutive_windows],
              ['Agrupamento (group_by)', item.group_by || item.detection_key],
              ['HAVING real', havingFor(item.name || item.vector)],
            ]} />
            <div className="v2-note" style={{ marginTop: 8 }}>
              Nos vetores inbound a cardinalidade de origem <b>nao</b> participa do HAVING: ela e
              evidencia de forma do trafego (ver "Forma do trafego" no drawer da anomalia).
            </div>
          </Section>
          <Section title="3 - Escopo e filtros">
            <Cells entries={[
              ['Escopo', item.scope],
              ['src_cidr', item.src_cidr],
              ['dst_cidr', item.dst_cidr],
              ['src_port', item.src_port],
              ['dst_port', item.dst_port],
              ['sensor', item.sensor_name || item.sensor_id],
              ['interface (ifIndex)', item.interface_if_index],
              ['input_if / output_if', `${item.input_if || '-'} / ${item.output_if || '-'}`],
            ]} />
          </Section>
          <Section title="4 - Resposta e mitigacao (configuracao)">
            <Cells entries={[
              ['Severidade', item.severity],
              ['Acao de resposta', item.response_action || item.response],
              ['Mitigacao habilitada', item.mitigation_enabled ? 'sim' : 'nao'],
              ['Modo de mitigacao', item.mitigation_mode],
              ['Perfil de resposta', item.response_profile_id],
              ['Cooldown (s)', item.cooldown_seconds],
              ['Duracao (s)', item.duration_seconds],
              ['Max anuncios ativos', item.max_active_announcements],
            ]} />
            <div className="v2-note" style={{ marginTop: 8 }}>
              A preview NAO altera elegibilidade de mitigacao: policy, perfil, FlowSpec e conector
              continuam exatamente como estao em producao.
            </div>
          </Section>
          <Section title="5 - Estado observado">
            <Cells entries={[
              ['Ultima checagem', item.last_check_at ? fmtTime(item.last_check_at) : ''],
              ['Ultimo match', item.last_match_at ? fmtTime(item.last_match_at) : ''],
              ['Ultima anomalia', item.last_anomaly_at ? fmtTime(item.last_anomaly_at) : ''],
              ['Motivo do ultimo skip', item.last_skip_reason],
              ['Notas', item.notes],
            ]} />
          </Section>
          <Section title="6 - Acoes (bloqueadas)">
            <ReadOnlyAction label="Editar" reason="PUT /api/attack-vectors/{id} e POST/PUT de regras - escrita." policy="B" />
            <ReadOnlyAction label="Duplicar" reason="POST /duplicate - escrita." policy="B" />
            <ReadOnlyAction label="Testar regra" reason="POST /test - ainda que seja consulta, o proxy bloqueia POST por padrao." policy="C" />
            <ReadOnlyAction label="Aplicar sugestao" reason="POST /apply e /apply-all alteram vetores reais." policy="B" />
          </Section>
        </div>
      </aside>
    </div>
  );
}

export default function Vectors() {
  const [tab, setTab] = useState('vectors');
  const [open, setOpen] = useState(null);
  const [templateId, setTemplateId] = useState(1);

  const vectors = useApi('/api/attack-vectors');
  const presets = useApi('/api/attack-vectors/templates');
  const dbTemplates = useApi('/api/attack-vector-templates');
  const suggestions = useApi('/api/attack-vector-suggestions?limit=100');
  const detectionStatus = useApi('/api/detection/status');
  const detectionTemplates = useApi('/api/detection/templates');
  const whitelist = useApi('/api/detection/whitelist');
  const rules = useApi(`/api/detection/templates/${templateId}/rules`);

  const vectorRows = vectors.data?.items || [];
  const presetRows = presets.data?.items || [];
  const dbTemplateRows = dbTemplates.data?.items || [];
  const suggestionRows = suggestions.data?.items || [];
  const templateRows = detectionTemplates.data?.items || [];
  const whitelistRows = whitelist.data?.items || [];
  const ruleRows = rules.data?.items || [];
  const statusData = detectionStatus.data || {};

  const activeTemplates = useMemo(() => templateRows.filter((t) => t.active !== false), [templateRows]);
  const inboundUdp = useMemo(
    () => vectorRows.filter((v) => String(v.direction) === 'receives' && String(v.protocol).toLowerCase() === 'udp').length,
    [vectorRows],
  );

  return (
    <div className="page">
      <div className="v2-tabs">
        {TABS.map(([id, label]) => (
          <button key={id} className={tab === id ? 'v2-tab on' : 'v2-tab'} onClick={() => setTab(id)}>{label}</button>
        ))}
        <span className="v2-tab-spacer" />
        <Badge tone="info">{vectorRows.length} vetores</Badge>
        <Badge tone="muted">{ruleRows.length} regras do template #{templateId}</Badge>
        <Badge tone="warning">{inboundUdp} UDP inbound</Badge>
      </div>

      <div className="v2-readonly-note">
        <Badge tone="critical">SOMENTE LEITURA</Badge>
        <span>CRUD de vetores/regras/templates/whitelist, teste de regra e apply de sugestao nao sao executados pela preview.</span>
      </div>

      {tab === 'vectors' ? (
        <Panel title="Vetores de ataque" subtitle="attack_vectors - condicao real de cada detector" badge={vectorRows.length} badgeTone={vectors.error ? 'warning' : 'info'}>
          {vectors.error ? <ErrorBox message={vectors.error} /> : null}
          {vectors.loading ? <Loading /> : (
            <Table
              columns={[
                { key: 'id', label: 'ID' },
                { key: 'display_name', label: 'Vetor', render: (r) => r.display_name || r.name },
                { key: 'name', label: 'Nome tecnico' },
                { key: 'direction', label: 'Direcao', render: (r) => <DirectionBadge direction={r.direction} /> },
                { key: 'protocol', label: 'Protocolo' },
                { key: 'threshold', label: 'Threshold', render: (r) => `${fmtNumber(r.threshold_value)} ${r.threshold_unit || ''}` },
                { key: 'severity', label: 'Severidade', render: (r) => <SeverityBadge severity={r.severity} /> },
                { key: 'mitigation_enabled', label: 'Mitig.', render: (r) => (r.mitigation_enabled ? 'sim' : 'nao') },
                { key: 'abrir', label: '', render: (r) => <button className="control" onClick={() => setOpen({ kind: 'vector', row: r })}>detalhe</button> },
              ]}
              rows={vectorRows}
              keyFor={(r) => r.id}
              empty="Nenhum vetor retornado."
            />
          )}
          <div className="v2-note" style={{ marginTop: 8 }}>
            Presets embutidos no backend: {presetRows.length} - templates em banco: {dbTemplateRows.length}
            {dbTemplateRows.length ? ` (${dbTemplateRows.map((t) => `${t.name}: ${t.vector_count} vetores`).join(', ')})` : ''}
          </div>
        </Panel>
      ) : null}

      {tab === 'rules' ? (
        <>
          <Panel title="Scheduler das regras" subtitle="detection/status" badge={statusData.rules_enabled != null ? `${statusData.rules_enabled} habilitadas` : '-'} badgeTone={detectionStatus.error ? 'warning' : 'info'}>
            {detectionStatus.error ? <ErrorBox message={detectionStatus.error} /> : null}
            {detectionStatus.loading ? <Loading /> : (
              <Cells entries={[
                ['Deteccao habilitada', statusData.enabled ? 'sim' : 'nao'],
                ['Scheduler', statusData.scheduler_running ? 'executando' : 'parado'],
                ['Intervalo (s)', statusData.interval_seconds],
                ['Ultima execucao', statusData.last_run_at ? fmtTime(statusData.last_run_at) : ''],
                ['Regras avaliadas', statusData.rules_evaluated_last_run],
                ['Anomalias criadas', statusData.anomalies_created_last_run],
                ['Ultimo erro', statusData.last_error],
              ]} />
            )}
          </Panel>
          <Panel title="Templates de deteccao" subtitle="Escolha o template para listar as regras reais" badge={activeTemplates.length} badgeTone="info">
            <div className="v2-tabs" style={{ padding: 0, border: 0 }}>
              {templateRows.map((t) => (
                <button key={t.id} className={templateId === t.id ? 'v2-tab on' : 'v2-tab'} onClick={() => setTemplateId(t.id)}>
                  #{t.id} {t.name} ({t.rule_count} regras)
                </button>
              ))}
            </div>
          </Panel>
          <Panel title={`Regras do template #${templateId}`} subtitle="detection_template_rules - threshold real e group_by" badge={ruleRows.length} badgeTone={rules.error ? 'warning' : 'info'}>
            {rules.error ? <ErrorBox message={rules.error} /> : null}
            {rules.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'id', label: 'ID' },
                  { key: 'vector', label: 'Regra' },
                  { key: 'direction', label: 'Direcao', render: (r) => <DirectionBadge direction={r.direction} /> },
                  { key: 'protocol', label: 'Proto' },
                  { key: 'metric', label: 'Metrica' },
                  { key: 'limits', label: 'warn / crit', render: (r) => `${fmtNumber(r.warning_value)} / ${fmtNumber(r.critical_value)}` },
                  { key: 'group_by', label: 'group_by' },
                  { key: 'response', label: 'Resposta' },
                  { key: 'last_skip_reason', label: 'Ultimo skip' },
                  { key: 'abrir', label: '', render: (r) => <button className="control" onClick={() => setOpen({ kind: 'rule', row: r })}>detalhe</button> },
                ]}
                rows={ruleRows}
                keyFor={(r) => r.id}
                empty={<EmptyState title="Sem regras neste template" hint="Selecione outro template ou confirme o id real." />}
              />
            )}
          </Panel>
        </>
      ) : null}

      {tab === 'templates' ? (
        <>
          <Panel title="Templates em banco" subtitle="attack_vector_templates" badge={dbTemplateRows.length} badgeTone="info">
            {dbTemplates.error ? <ErrorBox message={dbTemplates.error} /> : null}
            {dbTemplates.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'id', label: 'ID' },
                  { key: 'name', label: 'Template' },
                  { key: 'description', label: 'Descricao' },
                  { key: 'enabled', label: 'Habilitado', render: (r) => (r.enabled ? 'sim' : 'nao') },
                  { key: 'learn_enabled', label: 'Aprendizado', render: (r) => (r.learn_enabled ? `sim (${r.learn_days} dias)` : 'nao') },
                  { key: 'vector_count', label: 'Vetores' },
                ]}
                rows={dbTemplateRows}
                keyFor={(r) => r.id}
                empty="Nenhum template em banco."
              />
            )}
          </Panel>
          <Panel title="Presets embutidos" subtitle="list_attack_vector_presets (somente leitura)" badge={presetRows.length} badgeTone="info">
            {presets.error ? <ErrorBox message={presets.error} /> : null}
            {presets.loading ? <Loading /> : (
              <Table
                columns={[
                  { key: 'name', label: 'Preset' },
                  { key: 'direction', label: 'Direcao', render: (r) => <DirectionBadge direction={r.direction} /> },
                  { key: 'protocol', label: 'Proto' },
                  { key: 'threshold', label: 'Threshold', render: (r) => `${fmtNumber(r.threshold_value)} ${r.threshold_unit || ''}` },
                  { key: 'ports', label: 'src / dst port', render: (r) => `${r.src_port || '-'} / ${r.dst_port || '-'}` },
                  { key: 'severity', label: 'Severidade', render: (r) => <SeverityBadge severity={r.severity} /> },
                ]}
                rows={presetRows}
                keyFor={(r) => r.id}
                empty="Nenhum preset retornado."
              />
            )}
          </Panel>
        </>
      ) : null}

      {tab === 'whitelist' ? (
        <Panel title="Whitelist de deteccao" subtitle="detection_whitelist" badge={whitelistRows.length} badgeTone={whitelist.error ? 'warning' : 'info'}>
          {whitelist.error ? <ErrorBox message={whitelist.error} /> : null}
          {whitelist.loading ? <Loading /> : (
            <Table
              columns={[
                { key: 'id', label: 'ID' },
                { key: 'name', label: 'Nome' },
                { key: 'type', label: 'Tipo' },
                { key: 'src_cidr', label: 'src_cidr' },
                { key: 'dst_cidr', label: 'dst_cidr' },
                { key: 'protocol', label: 'Proto' },
                { key: 'vector', label: 'Vetor' },
                { key: 'active', label: 'Ativa', render: (r) => (r.active ? 'sim' : 'nao') },
              ]}
              rows={whitelistRows}
              keyFor={(r) => r.id}
              empty={<EmptyState title="Whitelist vazia" hint="Nenhuma excecao cadastrada na base real." />}
            />
          )}
          <div style={{ marginTop: 8 }}>
            <ReadOnlyAction label="Adicionar excecao" reason="POST /api/detection/whitelist - escrita." policy="B" />
          </div>
        </Panel>
      ) : null}

      {tab === 'suggestions' ? (
        <Panel title="Sugestoes de limiar (aprendizado)" subtitle="attack_vector_suggestions" badge={suggestionRows.length} badgeTone={suggestions.error ? 'warning' : 'info'}>
          {suggestions.error ? <ErrorBox message={suggestions.error} /> : null}
          {suggestions.loading ? <Loading /> : (
            <Table
              columns={[
                { key: 'id', label: 'ID' },
                { key: 'domain_type', label: 'Dominio' },
                { key: 'direction', label: 'Direcao', render: (r) => <DirectionBadge direction={r.direction} /> },
                { key: 'decoder', label: 'Decoder' },
                { key: 'threshold_value', label: 'Sugerido', render: (r) => `${fmtNumber(r.threshold_value)} ${r.threshold_unit || ''}` },
                { key: 'margin_percent', label: 'Margem %' },
                { key: 'confidence', label: 'Confianca', render: (r) => fmtNumber(r.confidence, 2) },
                { key: 'attack_shape', label: 'Forma' },
                { key: 'applied_at', label: 'Aplicada', render: (r) => (r.applied_at ? fmtTime(r.applied_at) : 'nao') },
              ]}
              rows={suggestionRows}
              keyFor={(r) => r.id}
              empty={<EmptyState title="Sem sugestoes" hint="O aprendizado de limiar nao gerou sugestoes pendentes." />}
            />
          )}
          <div style={{ marginTop: 8 }}>
            <ReadOnlyAction label="Aplicar sugestao / apply-all" reason="POST altera vetores reais de producao." policy="B" />
          </div>
        </Panel>
      ) : null}

      {open ? <RowDrawer kind={open.kind} row={open.row} onClose={() => setOpen(null)} /> : null}
    </div>
  );
}
