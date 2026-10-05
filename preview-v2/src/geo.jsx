import React, { useEffect, useState } from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Panel, ReadOnlyAction, Table, fmtNumber, fmtTime, useApi,
} from './shared.jsx';

/**
 * LOTE 2A (somente leitura):
 *   Mapa Global    -> /api/geo/flows           (endpoint pesado: pode dar 504/timeout)
 *   Clientes/Zonas -> /api/ip-zones
 *   Prefixos       -> /api/ip-zones/:id/prefixes   (ip_zone_prefixes; NAO usar /api/prefixes legacy)
 *   CGNAT          -> /api/cgnat/config | pools | mappings | imports
 */

function Nota({ children }) {
  return <div className="v2-readonly-note">Somente leitura · {children}</div>;
}

function Kpis({ itens }) {
  const lista = (itens || []).filter(Boolean);
  if (!lista.length) return null;
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

// ------------------------------------------------------- MAPA GLOBAL
export function GlobalMapPage() {
  // DECISAO (registrada): /api/geo/flows foi medido em ~60 s com 504 no proxy.
  // Como cada entrada na tela dispararia esse request, o carregamento no Preview
  // e SOB DEMANDA (botao). Nao mascaramos o erro nem aumentamos timeout.
  const [carregar, setCarregar] = useState(false);
  const geo = useApi('/api/geo/flows', { enabled: carregar, deps: [carregar] });
  const d = geo.data || {};
  const nodes = Array.isArray(d.nodes) ? d.nodes : [];
  const links = Array.isArray(d.links) ? d.links : [];
  const lento = Boolean(geo.error) && /504|timeout|timed out|aborted/i.test(String(geo.error));

  return (
    <>
      <Nota>o mapa representa <b>tráfego / fluxos geográficos agregados</b> na janela — node = cidade/país/ASN/IP, link = fluxo agregado origem → destino. Não é topologia física.</Nota>
      <Panel title="Mapa Global" subtitle="fluxos agregados por origem → destino (janela padrão do backend)"
        badge={!carregar ? 'sob demanda' : geo.error ? (lento ? 'timeout (504)' : 'Indisponível') : `${nodes.length} nós · ${links.length} vínculos`}
        badgeTone={!carregar || geo.error ? 'warning' : 'info'}
        actions={<button type="button" className="control" onClick={() => setCarregar(true)} disabled={carregar}>
          {carregar ? 'Consultando…' : 'Carregar mapa'}
        </button>}>
        <Kpis itens={[
          ['agrupamento', d.group_by || 'padrão do backend'],
          ['nós', nodes.length],
          ['vínculos', links.length],
          ['janela', d.range_minutes ? `${d.range_minutes} min` : '—'],
        ]} />
        {!carregar ? (
          <div className="v2-section">
            <p className="subtle">
              A consulta <code>/api/geo/flows</code> é pesada: medida em <b>~60 s</b>, com <b>504</b> no proxy.
              Para não travar a navegação, o carregamento é sob demanda.
            </p>
          </div>
        ) : geo.loading ? <Loading /> : geo.error ? (
          <div className="v2-section">
            <ErrorBox message={lento
              ? 'O endpoint /api/geo/flows excedeu o tempo limite do proxy (504). É um endpoint pesado — nenhum dado fictício é exibido.'
              : geo.error} />
            <p className="subtle" style={{ marginTop: 8 }}>
              A tela continua responsiva; recarregue para tentar novamente. Nenhum backend foi alterado.
            </p>
          </div>
        ) : nodes.length === 0 && links.length === 0 ? (
          <EmptyState title="Sem fluxos geográficos na janela" hint="O endpoint respondeu, mas não há agregação para o período." />
        ) : (
          <>
            <Table
              columns={[
                { key: 'label', label: 'Node', render: (r) => r.label || r.name || r.key || r.city || r.asn || r.ip || '—' },
                { key: 'kind', label: 'Tipo', render: (r) => r.kind || r.type || '—' },
                { key: 'country', label: 'País' },
                { key: 'zone_name', label: 'Zona' },
                { key: 'bytes', label: 'Tráfego', render: (r) => fmtNumber(r.bytes) },
                { key: 'bps', label: 'Bits/s', render: (r) => fmtNumber(r.bps) },
              ]}
              rows={nodes}
              keyFor={(r, i) => r.id || r.key || i}
            />
            {links.length > 0 && (
              <Table
                columns={[
                  { key: 'source', label: 'Origem', render: (r) => r.source || r.src || '—' },
                  { key: 'target', label: 'Destino', render: (r) => r.target || r.dst || '—' },
                  { key: 'bytes', label: 'Bytes', render: (r) => fmtNumber(r.bytes) },
                  { key: 'flows', label: 'Flows', render: (r) => fmtNumber(r.flows) },
                ]}
                rows={links}
                keyFor={(r, i) => `${r.source}-${r.target}-${i}`}
              />
            )}
          </>
        )}
      </Panel>
    </>
  );
}

// -------------------------------------------- CLIENTES / ZONAS
export function ZonesPage({ onNavigate }) {
  const zonas = useApi('/api/ip-zones');
  const itens = Array.isArray(zonas.data?.items) ? zonas.data.items : [];
  const [zonaId, setZonaId] = useState(null);
  const zona = itens.find((z) => z.id === zonaId) || null;
  const prefixPath = zonaId ? `/api/ip-zones/${zonaId}/prefixes` : null;
  const prefixos = useApi(prefixPath, { enabled: Boolean(prefixPath), deps: [prefixPath] });
  const lista = Array.isArray(prefixos.data?.items) ? prefixos.data.items : [];

  return (
    <>
      <Nota><b>ip_zones</b> é o modelo canônico de cliente/escopo. Clique numa zona para ver os prefixos de <b>ip_zone_prefixes</b>.</Nota>
      <Panel title="Clientes / Zonas" subtitle="zonas canônicas de cliente (ip_zones)"
        badge={zonas.error ? 'Indisponível' : `${itens.length} zona(s)`} badgeTone={zonas.error ? 'warning' : 'info'}>
        {zonas.loading ? <Loading /> : zonas.error ? <ErrorBox message={zonas.error} /> : itens.length === 0 ? (
          <EmptyState title="Nenhuma zona" hint="Nada retornado pelo servidor." />
        ) : (
          <Table
            onRowClick={(r) => setZonaId(r.id)}
            columns={[
              { key: 'id', label: 'ID' },
              { key: 'name', label: 'Zona' },
              { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativa' : 'inativa'}</Badge> },
              { key: 'subscriber_addressing_mode', label: 'Addressing' },
              { key: 'detection_template_name', label: 'Template' },
              { key: 'connector_name', label: 'Conector' },
              { key: 'prefix_count', label: 'Prefixos', render: (r) => `${r.active_prefix_count ?? 0}/${r.total_prefix_count ?? r.prefix_count ?? 0}` },
              { key: 'description', label: 'Descrição' },
            ]}
            rows={itens}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
      {zona && (
        <Panel title={`Prefixos · ${zona.name}`} subtitle="ip_zone_prefixes da zona selecionada"
          badge={prefixos.error ? 'Indisponível' : `${lista.length}`} badgeTone={prefixos.error ? 'warning' : 'info'}
          actions={<button type="button" className="control" onClick={() => setZonaId(null)}>Fechar</button>}>
          {prefixos.loading ? <Loading /> : prefixos.error ? <ErrorBox message={prefixos.error} /> : lista.length === 0 ? (
            <EmptyState title="Zona sem prefixos" hint="Nenhum prefixo cadastrado em ip_zone_prefixes para esta zona." />
          ) : (
            <Table
              columns={[
                { key: 'cidr', label: 'CIDR' },
                { key: 'family', label: 'Família', render: (r) => (String(r.cidr || '').includes(':') ? 'IPv6' : 'IPv4') },
                { key: 'prefix_type', label: 'Tipo' },
                { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativo' : 'inativo'}</Badge> },
                { key: 'name', label: 'Nome' },
                { key: 'description', label: 'Descrição' },
                { key: 'detection_template_name', label: 'Template' },
              ]}
              rows={lista}
              keyFor={(r) => r.id}
            />
          )}
        </Panel>
      )}
      <div className="v2-section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <ReadOnlyAction label="Nova zona" />
        <ReadOnlyAction label="Novo prefixo" />
        {onNavigate ? <button type="button" className="control" onClick={() => onNavigate('prefixes')}>Ver todos os prefixos</button> : null}
      </div>
    </>
  );
}

// -------------------------------------------- PREFIXOS
export function PrefixesPage({ onNavigate }) {
  const zonas = useApi('/api/ip-zones');
  const itens = Array.isArray(zonas.data?.items) ? zonas.data.items : [];
  const [zonaId, setZonaId] = useState(null);
  const selecionada = zonaId ?? (itens[0]?.id ?? null);
  const prefixPath = selecionada ? `/api/ip-zones/${selecionada}/prefixes` : null;
  const prefixos = useApi(prefixPath, { enabled: Boolean(prefixPath), deps: [prefixPath] });
  useEffect(() => {
    // complementar: assim que as zonas chegam, seleciona a primeira (sem gerar request nulo)
    if (zonaId === null && itens.length > 0) setZonaId(itens[0].id);
  }, [itens, zonaId]);
  const lista = Array.isArray(prefixos.data?.items) ? prefixos.data.items : [];
  const zona = itens.find((z) => z.id === selecionada) || null;

  return (
    <>
      <Nota>prefixos vêm de <b>ip_zone_prefixes</b> (endpoint <code>/api/ip-zones/:id/prefixes</code>). A tabela legacy <b>prefixes</b> está vazia/obsoleta e não é usada.</Nota>
      <Panel title="Prefixos" subtitle="prefixos por zona/cliente"
        badge={prefixos.error ? 'Indisponível' : `${lista.length} prefixo(s)`} badgeTone={prefixos.error ? 'warning' : 'info'}
        filters={(
          <select className="control" value={selecionada ?? ''} onChange={(e) => setZonaId(Number(e.target.value))}>
            {itens.map((z) => <option key={z.id} value={z.id}>{z.name}</option>)}
          </select>
        )}>
        <Kpis itens={[
          ['zona', zona ? zona.name : '—'],
          ['prefixos na zona', lista.length],
          ['ativos', lista.filter((p) => p.active).length],
          ['IPv6', lista.filter((p) => String(p.cidr || '').includes(':')).length],
        ]} />
        {zonas.loading || prefixos.loading ? <Loading /> : prefixos.error ? <ErrorBox message={prefixos.error} /> : lista.length === 0 ? (
          <EmptyState title="Zona sem prefixos" hint={itens.length ? 'Selecione outra zona ou cadastre prefixos (bloqueado no preview).' : 'Nenhuma zona retornada pelo servidor.'} />
        ) : (
          <Table
            columns={[
              { key: 'cidr', label: 'CIDR' },
              { key: 'family', label: 'Família', render: (r) => (String(r.cidr || '').includes(':') ? 'IPv6' : 'IPv4') },
              { key: 'prefix_type', label: 'Tipo' },
              { key: 'zone_name', label: 'Zona' },
              { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativo' : 'inativo'}</Badge> },
              { key: 'description', label: 'Descrição' },
              { key: 'updated_at', label: 'Atualizado', render: (r) => (r.updated_at ? fmtTime(r.updated_at) : '—') },
            ]}
            rows={lista}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
      <div className="v2-section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <ReadOnlyAction label="Novo prefixo" />
        <ReadOnlyAction label="Desativar selecionados" />
        {onNavigate ? <button type="button" className="control" onClick={() => onNavigate('zones')}>Voltar para Clientes / Zonas</button> : null}
      </div>
    </>
  );
}

// -------------------------------------------- CGNAT
export function CgnatPage() {
  const config = useApi('/api/cgnat/config');
  const pools = useApi('/api/cgnat/pools');
  const mappings = useApi('/api/cgnat/mappings');
  const imports = useApi('/api/cgnat/imports');
  const d = config.data || {};
  const poolsItens = Array.isArray(pools.data?.items) ? pools.data.items : [];
  const mapaItens = Array.isArray(mappings.data?.items) ? mappings.data.items : [];
  const importItens = Array.isArray(imports.data?.items) ? imports.data.items : [];

  return (
    <>
      <Nota>a resolução de assinante exige <b>IP público + porta pública + protocolo + timestamp</b>. Nunca inferimos assinante só pelo IP.</Nota>
      <Panel title="CGNAT" subtitle="pools, mapeamentos e imports (somente leitura)"
        badge={pools.error ? 'Indisponível' : `${poolsItens.length} pool(s)`} badgeTone={pools.error ? 'warning' : 'info'}>
        <Kpis itens={[
          ['pools', poolsItens.length],
          ['mappings', mapaItens.length],
          ['imports', importItens.length],
          ['limites', d.limits ? Object.keys(d.limits).length : '—'],
        ]} />
        {pools.loading ? <Loading /> : pools.error ? <ErrorBox message={pools.error} /> : poolsItens.length === 0 ? (
          <EmptyState title="Nenhum pool CGNAT" hint="Nada retornado pelo servidor." />
        ) : (
          <Table
            columns={[
              { key: 'name', label: 'Pool' },
              { key: 'prefix', label: 'Prefixo' },
              { key: 'mode', label: 'Modo' },
              { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativo' : 'inativo'}</Badge> },
              { key: 'notes', label: 'Notas' },
            ]}
            rows={poolsItens}
            keyFor={(r) => r.id}
          />
        )}
      </Panel>
      <div className="v2-grid">
        <Panel title="Mapeamentos" subtitle="pública → privada · correlação exige IP+porta+protocolo+timestamp"
          badge={mappings.error ? 'Indisponível' : `${mapaItens.length} (limit 200)`} badgeTone={mappings.error ? 'warning' : 'info'}>
          {mappings.loading ? <Loading /> : mappings.error ? <ErrorBox message={mappings.error} /> : mapaItens.length === 0 ? (
            <EmptyState title="Sem mapeamentos" hint="Nenhum registro retornado." />
          ) : (
            <Table
              columns={[
                { key: 'public_ip', label: 'IP público' },
                { key: 'port', label: 'Portas', render: (r) => `${r.port_start ?? '—'}–${r.port_end ?? '—'}` },
                { key: 'protocol', label: 'Proto' },
                { key: 'private_ip', label: 'IP privado' },
                { key: 'subscriber', label: 'Assinante', render: (r) => (r.subscriber_name || (r.subscriber_id ? `#${r.subscriber_id}` : 'não resolvido')) },
                { key: 'confidence', label: 'Confiança', render: (r) => (r.confidence != null ? String(r.confidence) : '—') },
                { key: 'valid_from', label: 'Válido de', render: (r) => (r.valid_from ? fmtTime(r.valid_from) : '—') },
                { key: 'valid_until', label: 'Até', render: (r) => (r.valid_until ? fmtTime(r.valid_until) : '—') },
                { key: 'active', label: 'Status', render: (r) => <Badge tone={r.active ? 'success' : 'warning'}>{r.active ? 'ativo' : 'inativo'}</Badge> },
              ]}
              rows={mapaItens}
              keyFor={(r, i) => r.id || i}
            />
          )}
        </Panel>
        <Panel title="Imports / batches" subtitle={`cargas de mapeamento · limits: ${imports.data?.limits ? Object.keys(imports.data.limits).join(', ') : '—'}`}
          badge={imports.error ? 'Indisponível' : `${importItens.length}`} badgeTone={imports.error ? 'warning' : 'info'}>
          {imports.loading ? <Loading /> : imports.error ? <ErrorBox message={imports.error} /> : importItens.length === 0 ? (
            <EmptyState title="Sem imports" hint="Nenhum batch retornado." />
          ) : (
            <Table
              columns={[
                { key: 'id', label: 'Batch' },
                { key: 'status', label: 'Status', render: (r) => <Badge tone={/done|ok|success/i.test(String(r.status)) ? 'success' : 'warning'}>{r.status || '—'}</Badge> },
                { key: 'rows', label: 'Linhas', render: (r) => fmtNumber(r.rows ?? r.total_rows) },
                { key: 'created_at', label: 'Criado', render: (r) => (r.created_at ? fmtTime(r.created_at) : '—') },
              ]}
              rows={importItens}
              keyFor={(r, i) => r.id || i}
            />
          )}
        </Panel>
      </div>
      <div className="v2-section" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <ReadOnlyAction label="Novo pool" />
        <ReadOnlyAction label="Importar mapeamentos" />
        <ReadOnlyAction label="Resolver assinante" reason="Exige IP público + porta + protocolo + timestamp" />
      </div>
    </>
  );
}
