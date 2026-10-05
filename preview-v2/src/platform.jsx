import React from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Panel, ReadOnlyAction, Table, fmtNumber, fmtTime, useApi,
} from './shared.jsx';

/**
 * LOTE 1 da migracao para o Preview V2 (somente leitura):
 *   Midia      -> /api/media
 *   Codecs     -> /api/flow-codecs (+ /options)
 *   Banco      -> /api/database/status | /tables | /retention
 *   Sistema    -> /api/system/containers | resources | disk-guard | dashboard-cache
 *
 * Nenhuma acao de escrita: os botoes existem desabilitados e a pagina se
 * identifica como somente leitura.
 */

function ReadOnlyBanner({ acoes }) {
  return <div className="v2-readonly-note">Somente leitura · {acoes}</div>;
}

function ReadOnlyButton({ children }) {
  return <ReadOnlyAction label={children} />;
}

function Cells({ pares }) {
  const lista = (pares || []).filter(Boolean);
  return (
    <div className="v2-kpis">
      {lista.map(([rotulo, valor]) => (
        <div className="v2-kpi" key={rotulo}>
          <span style={{ display: 'block', color: 'var(--dim)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.05em' }}>{rotulo}</span>
          <b style={{ display: 'block', marginTop: 4, fontSize: 12, fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace' }}>
            {valor === null || valor === undefined || valor === '' ? '—' : String(valor)}
          </b>
        </div>
      ))}
    </div>
  );
}

function escalares(obj, prefixo = '') {
  if (!obj || typeof obj !== 'object') return [];
  const linhas = [];
  for (const [chave, valor] of Object.entries(obj)) {
    if (valor && typeof valor === 'object') continue;
    linhas.push([`${prefixo}${chave}`, valor]);
  }
  return linhas;
}

// ---------------------------------------------------------------- MIDIA
export function MediaPage() {
  const media = useApi('/api/media');
  const d = media.data || {};
  const itens = Array.isArray(d.items) ? d.items : [];

  return (
    <div className="v2-page">
      <ReadOnlyBanner acoes="As integrações abaixo são exibidas como estão configuradas." />
      <Panel title="Mídia" subtitle="integrações de notificação (webhook / Telegram via n8n)"
        badge={media.error ? 'Indisponível' : `${itens.length} integração(ões)`} badgeTone={media.error ? 'warning' : 'info'}>
        {media.loading ? <Loading /> : media.error ? <ErrorBox message={media.error} /> : itens.length === 0 ? (
          <EmptyState title="Nenhuma integração de mídia" hint="Nada configurado no servidor." />
        ) : (
          <Table
            columns={[
              { key: 'name', label: 'Integração' },
              { key: 'type', label: 'Tipo' },
              { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativo' : 'inativo'}</Badge> },
              { key: 'minimum_severity', label: 'Severidade mín.' },
              { key: 'event_types', label: 'Eventos', render: (r) => (Array.isArray(r.event_types) ? r.event_types.length : 0) },
              { key: 'has_secret', label: 'Segredo', render: (r) => (r.has_secret ? 'configurado' : '—') },
              { key: 'last_test_at', label: 'Último teste', render: (r) => (r.last_test_at ? fmtTime(r.last_test_at) : 'nunca') },
              { key: 'last_test_status', label: 'Resultado', render: (r) => (
                r.last_test_status
                  ? <Badge tone={/ok|success/i.test(String(r.last_test_status)) ? 'ok' : 'warn'}>{String(r.last_test_status)}{r.last_test_http_status ? ` · HTTP ${r.last_test_http_status}` : ''}</Badge>
                  : '—'
              ) },
              { key: 'last_test_duration_ms', label: 'Duração', render: (r) => (r.last_test_duration_ms ? `${r.last_test_duration_ms} ms` : '—') },
            ]}
            rows={itens}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
      <div className="v2-grid">
        <Panel title="Última entrega" subtitle="dispatch mais recente">
          {media.loading ? <Loading /> : <Cells pares={escalares(d.last_dispatch, '')} />}
        </Panel>
        <Panel title="Fila" subtitle="jobs pendentes">
          {media.loading ? <Loading /> : <Cells pares={[['pending_jobs', d.pending_jobs], ['tipos suportados', Array.isArray(d.types) ? d.types.join(', ') : '—']]} />}
        </Panel>
      </div>
      <div className="v2-section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <ReadOnlyButton>Nova integração</ReadOnlyButton>
        <ReadOnlyButton>Testar entrega</ReadOnlyButton>
        <ReadOnlyButton>Rotacionar segredo</ReadOnlyButton>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- CODECS
export function CodecsPage() {
  const codecs = useApi('/api/flow-codecs');
  const options = useApi('/api/flow-codecs/options');
  const itens = Array.isArray(codecs.data?.items) ? codecs.data.items : [];
  const ativos = itens.filter((c) => c.active).length;
  const builtin = itens.filter((c) => c.builtin).length;

  return (
    <div className="v2-page">
      <ReadOnlyBanner acoes="Codecs definem como o tráfego é classificado por protocolo/porta/papel." />
      <Panel title="Codecs" subtitle="classificação de flows · protocolo, portas, papéis e prioridade"
        badge={codecs.error ? 'Indisponível' : `${ativos}/${itens.length} ativos`} badgeTone={codecs.error ? 'warning' : 'info'}>
        {codecs.loading ? <Loading /> : codecs.error ? <ErrorBox message={codecs.error} /> : itens.length === 0 ? (
          <EmptyState title="Nenhum codec" hint="Nada retornado pelo servidor." />
        ) : (
          <Table
            columns={[
              { key: 'display_name', label: 'Codec', render: (r) => r.display_name || r.name },
              { key: 'name', label: 'Chave' },
              { key: 'protocol', label: 'Protocolo' },
              { key: 'ports', label: 'Portas', render: (r) => `${r.source_port ?? 'any'} → ${r.destination_port ?? 'any'}` },
              { key: 'direction', label: 'Direção' },
              { key: 'roles', label: 'Papéis', render: (r) => `${r.source_role || '—'} → ${r.destination_role || '—'}` },
              { key: 'specificity_priority', label: 'Prioridade' },
              { key: 'exclusive_group', label: 'Grupo excl.' },
              { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativo' : 'inativo'}</Badge> },
              { key: 'builtin', label: 'Origem', render: (r) => (r.builtin ? 'builtin' : (r.provider || 'custom')) },
            ]}
            rows={itens}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
      <div className="v2-grid">
        <Panel title="Opções" subtitle="domínios aceitos pelo cadastro">
          {options.loading ? <Loading /> : options.error ? <ErrorBox message={options.error} /> : (
            <Cells pares={[
              ['protocolos', Array.isArray(options.data?.protocols) ? options.data.protocols.join(', ') : '—'],
              ['direções', Array.isArray(options.data?.directions) ? options.data.directions.join(', ') : '—'],
              ['papéis', Array.isArray(options.data?.roles) ? options.data.roles.join(', ') : '—'],
              ['grupos exclusivos', Array.isArray(options.data?.exclusive_groups) ? options.data.exclusive_groups.join(', ') : '—'],
            ]} />
          )}
        </Panel>
        <Panel title="Cobertura" subtitle="resumo do cadastro">
          <Cells pares={[['codecs', itens.length], ['ativos', ativos], ['builtin', builtin], ['custom', itens.length - builtin]]} />
        </Panel>
      </div>
      <div className="v2-section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <ReadOnlyButton>Novo codec</ReadOnlyButton>
        <ReadOnlyButton>Testar codec</ReadOnlyButton>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- BANCO
export function DatabasePage() {
  const status = useApi('/api/database/status');
  const tabelas = useApi('/api/database/tables');
  const d = status.data || {};
  const rows = Array.isArray(tabelas.data?.items) ? tabelas.data.items : [];

  return (
    <div className="v2-page">
      <ReadOnlyBanner acoes="Indicadores de retenção e uso do banco de flows." />
      <Panel title="Banco de Dados" subtitle="saúde, volume, retenção e tabelas principais"
        badge={status.error ? 'Indisponível' : (d.clickhouse_ok && d.sqlite_ok ? 'operacional' : 'atenção')}
        badgeTone={status.error ? 'warning' : (d.clickhouse_ok && d.sqlite_ok ? 'success' : 'warning')}>
        {status.loading ? <Loading /> : status.error ? <ErrorBox message={status.error} /> : (
          <Cells pares={[
            ['ClickHouse', d.clickhouse_ok ? 'ok' : 'falha'],
            ['SQLite', d.sqlite_ok ? 'ok' : 'falha'],
            ['Flows', fmtNumber(d.flow_count)],
            ['Flow mais antigo', d.oldest_flow_time ? fmtTime(d.oldest_flow_time) : '—'],
            ['Flow mais recente', d.newest_flow_time ? fmtTime(d.newest_flow_time) : '—'],
            ['Tamanho ClickHouse', d.clickhouse_database_size_human || '—'],
            ['flow_raw', d.flow_raw_size_human || '—'],
            ['flow_1m', d.flow_1m_size_human || '—'],
            ['flow_tops_1m', d.flow_tops_1m_size_human || '—'],
            ['SQLite', d.sqlite_size_human || '—'],
            ['Disco livre', d.disk_free_human || '—'],
            ['Disco usado', `${d.disk_used_human || '—'} (${d.disk_used_percent ?? '—'}%)`],
            ['Retenção', d.retention_enabled ? 'ativa' : 'desativada'],
          ]} />
        )}
      </Panel>
      <Panel title="Tabelas" subtitle="volume por tabela" badge={rows.length}>
        {tabelas.loading ? <Loading /> : tabelas.error ? <ErrorBox message={tabelas.error} /> : rows.length === 0 ? (
          <EmptyState title="Sem tabelas" hint="Nada retornado pelo servidor." />
        ) : (
          <Table
            columns={[
              { key: 'table', label: 'Tabela' },
              { key: 'rows', label: 'Linhas', render: (r) => fmtNumber(r.rows) },
              { key: 'size_human', label: 'Tamanho' },
              { key: 'first_record', label: 'Primeiro registro', render: (r) => (r.first_record ? fmtTime(r.first_record) : '—') },
            ]}
            rows={rows}
            keyFor={(r) => r.table}
          />
        )}
      </Panel>
      <div className="v2-section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <ReadOnlyButton>Otimizar</ReadOnlyButton>
        <ReadOnlyButton>Aplicar TTL</ReadOnlyButton>
        <ReadOnlyButton>Limpeza manual</ReadOnlyButton>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- SISTEMA
export function SystemPage() {
  const recursos = useApi('/api/system/resources');
  const containers = useApi('/api/system/containers');
  const guard = useApi('/api/system/disk-guard');
  const cache = useApi('/api/system/dashboard-cache');
  const r = recursos.data || {};
  const g = guard.data || {};
  const c = cache.data || {};
  const containersItens = Array.isArray(containers.data?.items) ? containers.data.items : [];
  const warnings = Array.isArray(r.warnings) ? r.warnings : [];

  return (
    <div className="v2-page">
      <ReadOnlyBanner acoes="Saúde operacional dos componentes do GMJ-FLOW." />
      {warnings.length > 0 && (
        <Panel title="Avisos" subtitle="recursos sob atenção" badge={`${warnings.length}`} badgeTone="warn">
          <ul style={{ margin: 0, padding: '8px 12px 12px 26px', color: 'var(--muted)', fontSize: 11 }}>{warnings.map((w, i) => <li key={i}>{typeof w === 'string' ? w : JSON.stringify(w)}</li>)}</ul>
        </Panel>
      )}
      <Panel title="Recursos" subtitle="CPU, memória, disco e ingestão"
        badge={recursos.error ? 'Indisponível' : 'dados reais'} badgeTone={recursos.error ? 'warn' : 'info'}>
        {recursos.loading ? <Loading /> : recursos.error ? <ErrorBox message={recursos.error} /> : (
          <>
            <Cells pares={[
              ...escalares(r.cpu, 'cpu · '),
              ...escalares(r.memory, 'mem · '),
              ...escalares(r.disk, 'disco · '),
              ...escalares(r.ingestion, 'ingestão · '),
            ]} />
            <div className="v2-note" style={{ marginTop: 8 }}>
              ClickHouse e banco: {escalares(r.clickhouse).length + escalares(r.database).length} indicadores monitorados.
            </div>
          </>
        )}
      </Panel>
      <div className="v2-grid">
        <Panel title="Disk guard" subtitle="proteção de disco e limpezas"
          badge={g.state || (guard.error ? 'Indisponível' : '—')}
          badgeTone={g.state && /ok|normal/i.test(String(g.state)) ? 'success' : 'warning'}>
          {guard.loading ? <Loading /> : guard.error ? <ErrorBox message={guard.error} /> : (
            <Cells pares={[
              ['habilitado', g.enabled ? 'sim' : 'não'],
              ['livre', `${g.free_gb ?? '—'} GB (${g.free_percent ?? '—'}%)`],
              ['usado', `${g.used_percent ?? '—'}%`],
              ['estado', g.state || '—'],
              ['limpeza em curso', g.cleanup_running ? 'sim' : 'não'],
              ['última verificação', g.last_check_at ? fmtTime(g.last_check_at) : '—'],
              ['última limpeza', g.last_cleanup_at ? fmtTime(g.last_cleanup_at) : 'nunca'],
              ['motivo da limpeza', g.last_cleanup_reason || '—'],
            ]} />
          )}
        </Panel>
        <Panel title="Cache do dashboard" subtitle="acertos, entradas e pressão de memória">
          {cache.loading ? <Loading /> : cache.error ? <ErrorBox message={cache.error} /> : (
            <Cells pares={[
              ['modo', c.mode || '—'],
              ['habilitado', c.enabled ? 'sim' : 'não'],
              ['entradas', `${c.entries ?? '—'} / ${c.max_entries ?? '—'}`],
              ['uso', `${c.current_bytes ?? '—'} / ${c.effective_max_bytes ?? '—'} bytes`],
              ['hits', fmtNumber(c.hits)],
              ['misses', fmtNumber(c.misses)],
              ['evictions', fmtNumber(c.evictions)],
              ['pressão de memória', c.memory_pressure || '—'],
            ]} />
          )}
        </Panel>
      </div>
      <Panel title="Containers" subtitle="estado dos serviços do stack"
        badge={containers.error ? 'Indisponível' : `${containersItens.length}`} badgeTone={containers.error ? 'warning' : 'info'}>
        {containers.loading ? <Loading /> : containers.error ? <ErrorBox message={containers.error} /> : containersItens.length === 0 ? (
          <EmptyState title="Sem dados de containers"
            hint={containers.data?.error ? String(containers.data.error) : 'O backend não expôs a lista neste momento.'} />
        ) : (
          <Table
            columns={[
              { key: 'name', label: 'Container' },
              { key: 'service', label: 'Serviço' },
              { key: 'state', label: 'Estado', render: (x) => <Badge tone={/running/i.test(String(x.state)) ? 'success' : 'warning'}>{x.state || '—'}</Badge> },
              { key: 'status', label: 'Status' },
            ]}
            rows={containersItens}
            keyFor={(x, i) => x.id || x.name || i}
          />
        )}
      </Panel>
    </div>
  );
}
