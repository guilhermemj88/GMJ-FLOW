(function (root) {
  'use strict';

  const COUNTRY_CENTERS = Object.freeze({
    AR: [-38.4, -63.6], AU: [-25.3, 133.8], AT: [47.5, 14.6], BD: [23.7, 90.4], BE: [50.5, 4.5],
    BG: [42.7, 25.5], BR: [-14.2, -51.9], CA: [56.1, -106.3], CH: [46.8, 8.2], CL: [-35.7, -71.5],
    CN: [35.9, 104.2], CO: [4.6, -74.3], CZ: [49.8, 15.5], DE: [51.2, 10.5], DK: [56.3, 9.5],
    EG: [26.8, 30.8], ES: [40.5, -3.7], FI: [61.9, 25.7], FR: [46.2, 2.2], GB: [55.4, -3.4],
    GR: [39.1, 21.8], HK: [22.3, 114.2], HU: [47.2, 19.5], ID: [-0.8, 113.9], IE: [53.1, -8.2],
    IL: [31.0, 34.9], IN: [20.6, 79.0], IR: [32.4, 53.7], IT: [41.9, 12.6], JP: [36.2, 138.3],
    KR: [35.9, 127.8], MX: [23.6, -102.6], MY: [4.2, 101.9], NG: [9.1, 8.7], NL: [52.1, 5.3],
    NO: [60.5, 8.5], NZ: [-40.9, 174.9], PE: [-9.2, -75.0], PH: [12.9, 121.8], PK: [30.4, 69.3],
    PL: [51.9, 19.1], PT: [39.4, -8.2], RO: [45.9, 24.9], RS: [44.0, 21.0], RU: [61.5, 105.3],
    SA: [23.9, 45.1], SE: [60.1, 18.6], SG: [1.35, 103.8], TH: [15.9, 100.9], TR: [39.0, 35.2],
    TW: [23.7, 121.0], UA: [48.4, 31.2], US: [37.1, -95.7], AE: [23.4, 53.8], VN: [14.1, 108.3],
    ZA: [-30.6, 22.9]
  });
  const GMJ_CENTER = [-15.79, -47.88];
  let threatMap = null;
  let loading = false;

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  function number(value, digits = 0) {
    const parsed = Number(value || 0);
    return Number.isFinite(parsed) ? parsed.toLocaleString('pt-BR', { maximumFractionDigits: digits }) : '0';
  }

  function dateTime(value) {
    if (!value) return '-';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? esc(value) : parsed.toLocaleString('pt-BR');
  }

  function statusBadge(value) {
    const status = String(value || 'OFFLINE').toUpperCase();
    const css = status.toLowerCase().replace(/_/g, '-');
    return `<span class="threat-status-badge threat-status-${esc(css)}">${esc(status)}</span>`;
  }

  function sourceBadge(source) {
    const normalized = String(source || 'LEGACY_DETECTION').toUpperCase();
    if (normalized === 'GMJ_FLOW' || normalized === 'GMJ-FLOW') return '<span class="threat-source-badge source-gmj">GMJ-FLOW</span>';
    if (normalized === 'MANUAL') return '<span class="threat-source-badge source-manual">Manual</span>';
    if (normalized === 'CEREAL2_POLICY') return '<span class="threat-source-badge source-external">CEREAL2 POLICY</span>';
    if (normalized.includes('ALLOWLIST') || normalized.includes('EXCEPTION')) return '<span class="threat-source-badge source-allowlist">Allowlist/Exception</span>';
    return `<span class="threat-source-badge source-external">${esc(normalized.replace(/_/g, ' '))}</span>`;
  }

  function intelChips(items) {
    const sources = Array.isArray(items) ? items : [];
    return sources.length
      ? sources.map(item => `<span class="threat-intel-chip">${esc(item)}</span>`).join('')
      : '<span class="subtle">Sem match externo</span>';
  }

  function scoreClass(value) {
    const score = Number(value || 0);
    return score >= 85 ? 'high' : score >= 60 ? 'medium' : 'low';
  }

  function ensureMap() {
    const element = document.getElementById('threatGlobalMap');
    if (!element || !root.GeoFlowMap) return null;
    if (!threatMap) {
      threatMap = new root.GeoFlowMap(element, {
        title: 'Infraestrutura hostil observada',
        subtitle: 'Indicadores externos agregados por localização; o mapa não autoriza bloqueios',
        mode: 'flows', metric: 'flows', groupBy: 'country', interactive: false,
        rankingLimit: 12, routeLabelLimit: 10, fitMaxZoom: 4
      });
    }
    return threatMap;
  }

  function mapEdges(items) {
    return (items || []).map((item, index) => {
      const code = String(item.country_code || (String(item.key || '').length === 2 ? item.key : '')).toUpperCase();
      const center = COUNTRY_CENTERS[code];
      if (!center) return null;
      return {
        id: `intel-${index}-${item.key || code}`,
        src_label: item.label || item.organization || item.key || code,
        src_country: code,
        src_lat: center[0], src_lon: center[1],
        dst_label: 'GMJ-FLOW', dst_country: 'BR', dst_lat: GMJ_CENTER[0], dst_lon: GMJ_CENTER[1],
        flows: Number(item.count || item.unique_ips || 0), packets_s: 0, bits_s: 0,
        top_protocol: 'OTHER', top_asn_src: Number(item.asn || 0), top_asn_dst: 0
      };
    }).filter(Boolean);
  }

  function renderProviders(payload) {
    const items = payload.items || [];
    const canManage = typeof root.hasPermission === 'function' && root.hasPermission('anomalies.manage');
    document.getElementById('threatSummaryOnline').textContent = number(payload.summary?.online);
    document.getElementById('threatSummaryRecords').textContent = number(payload.summary?.records);
    document.getElementById('threatProviderCards').innerHTML = items.map(item => `
      <article class="threat-provider-card" data-provider="${esc(item.provider)}">
        <div class="threat-provider-card__header"><strong>${esc(item.display_name || item.provider)}</strong>${statusBadge(item.status)}</div>
        <div class="threat-provider-card__meta">
          <span>${number(item.item_count)} registros</span><span>•</span>
          <span>Sync: ${dateTime(item.last_sync)}</span><span>•</span>
          <span>Sucesso: ${dateTime(item.last_success)}</span><span>•</span>
          <span>Duração: ${number(item.last_sync_duration_ms)} ms</span><span>•</span>
          <span>Próxima: ${dateTime(item.next_sync)}</span><span>•</span>
          <span>Credencial: ${item.credential_configured ? 'configurada' : 'não configurada'}</span>
        </div>
        <div class="threat-provider-card__error">${esc(item.last_error || (item.credential_configured ? '' : 'Credencial não configurada'))}</div>
        <div class="threat-provider-card__actions">${canManage ? `
          <button type="button" class="btn btn-sm btn-outline-secondary" data-threat-action="test" data-provider="${esc(item.provider)}">Testar</button>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-threat-action="sync" data-provider="${esc(item.provider)}" ${item.enabled ? '' : 'disabled'}>Sync now</button>
          <button type="button" class="btn btn-sm ${item.enabled ? 'btn-outline-danger' : 'btn-outline-success'}" data-threat-action="toggle" data-enabled="${item.enabled ? 'true' : 'false'}" data-provider="${esc(item.provider)}">${item.enabled ? 'Desativar' : 'Ativar'}</button>` : '<span class="subtle">Somente leitura</span>'}
        </div>
      </article>`).join('') || '<div class="subtle">Nenhum provider configurado.</div>';
    const select = document.getElementById('threatProviderFilter');
    const selected = select.value;
    select.innerHTML = '<option value="">Todos</option>' + items.map(item => `<option value="${esc(item.provider)}">${esc(item.display_name || item.provider)}</option>`).join('');
    select.value = selected;
  }

  function renderVectors(payload) {
    const items = payload.items || [];
    document.getElementById('threatSummaryVectors').textContent = number(items.length);
    document.getElementById('threatVectorRows').innerHTML = items.map(item => {
      const features = item.features || {};
      const evidence = [
        features.unique_dst_ports ? `${number(features.unique_dst_ports)} portas` : '',
        features.unique_dst_ips ? `${number(features.unique_dst_ips)} destinos` : '',
        features.unique_sources ? `${number(features.unique_sources)} fontes` : '',
        features.pps ? `${number(features.pps, 1)} pps` : ''
      ].filter(Boolean).join(' · ') || '-';
      return `<tr>
        <td><strong>${esc(item.attack_type)}</strong><br><span class="subtle">${esc(item.direction || '-')}</span></td>
        <td>${esc(item.src_ip || 'distribuída')} → ${esc(item.target_prefix || item.target_ip || '-')}</td>
        <td><span class="threat-score ${scoreClass(item.detector_score)}">${number(item.detector_score)}</span><br><span class="subtle">conf. ${number(Number(item.confidence || 0) * 100, 1)}%</span></td>
        <td>${esc(evidence)}</td><td>${intelChips(item.intel_sources)}</td>
        <td>${item.campaign_id ? `<code>${esc(item.campaign_id)}</code>` : '-'}</td><td>${dateTime(item.last_seen)}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="7" class="text-muted">Nenhum Attack Vector recente.</td></tr>';
  }

  function renderCampaigns(payload) {
    const items = payload.items || [];
    document.getElementById('threatSummaryCampaigns').textContent = number(items.length);
    document.getElementById('threatCampaignRows').innerHTML = items.map(item => `<tr>
      <td><code>${esc(item.campaign_id)}</code><br><span class="subtle">${dateTime(item.last_seen)}</span></td>
      <td><strong>${esc(item.classification)}</strong><br>${esc(item.target_prefix || '-')}</td>
      <td><span class="threat-score ${scoreClass(item.coordination_score)}">${number(item.coordination_score)}</span><br><span class="subtle">${number(item.packets_per_second, 1)} pps</span></td>
      <td>${number(item.unique_sources)} / ${number(item.unique_source_asns)}</td><td>${intelChips(item.intel_sources)}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="text-muted">Nenhum Campaign Vector recente.</td></tr>';
  }

  function flowspecText(proposal) {
    if (!proposal || !proposal.action) return '-';
    const match = [proposal.src_prefix && `src ${proposal.src_prefix}`, proposal.dst_prefix && `dst ${proposal.dst_prefix}`,
      proposal.protocol, proposal.src_port && `sport ${proposal.src_port}`, proposal.dst_port && `dport ${proposal.dst_port}`,
      proposal.tcp_flags && `flags ${proposal.tcp_flags}`].filter(Boolean).join(' · ');
    return `${proposal.action}: ${match}`;
  }

  function renderDecisions(payload) {
    const items = payload.items || [];
    document.getElementById('threatSummaryAllowed').textContent = number(items.filter(item => item.decision === 'ALLOW_AUTO').length);
    document.getElementById('threatDecisionRows').innerHTML = items.map(item => `<tr>
      <td>${statusBadge(item.decision === 'ALLOW_AUTO' ? 'ONLINE' : 'DISABLED')}<br><strong>${esc(item.decision)}</strong></td>
      <td>${esc(item.classification)}</td>
      <td><span class="threat-score ${scoreClass(item.policy_score)}">${number(item.policy_score)}</span><br><span class="subtle">Groq ${number(Number(item.confidence || 0) * 100, 1)}%</span></td>
      <td>${sourceBadge(item.decision_source)}<br>${intelChips(item.intel_sources)}</td>
      <td><code class="threat-flowspec">${esc(flowspecText(item.proposal))}</code></td>
      <td>${item.ttl_seconds ? `${number(item.ttl_seconds)} s` : '-'}</td>
      <td>${esc(item.reason || item.non_mitigation_reason || '-')}</td><td>${dateTime(item.created_at)}</td>
    </tr>`).join('') || '<tr><td colspan="8" class="text-muted">Nenhuma decisão registrada.</td></tr>';
  }

  async function loadMap() {
    const query = new URLSearchParams({ group_by: document.getElementById('threatGroupFilter').value || 'country' });
    const provider = document.getElementById('threatProviderFilter').value;
    const classification = document.getElementById('threatClassificationFilter').value.trim();
    const tag = document.getElementById('threatTagFilter').value.trim();
    if (provider) query.set('provider', provider);
    if (classification) query.set('classification', classification);
    if (tag) query.set('tag', tag);
    const map = ensureMap();
    map?.setLoading('Carregando indicadores geográficos...');
    const payload = await apiRequest(`/api/threat-intelligence/map?${query}`);
    map?.setData({ edges: mapEdges(payload.items), metric: 'flows', group_by: 'country' }, { metric: 'flows', mode: 'flows', fit: true });
  }

  async function loadWorkspace() {
    if (loading) return;
    loading = true;
    document.getElementById('threatWorkspaceStatus').textContent = 'Atualizando inteligência e detecções...';
    try {
      const [providers, vectors, campaigns, decisions] = await Promise.all([
        apiRequest('/api/threat-intelligence/providers'), apiRequest('/api/threat-engine/attack-vectors?limit=200'),
        apiRequest('/api/threat-engine/campaigns?limit=100'), apiRequest('/api/threat-engine/policy-decisions?limit=200')
      ]);
      renderProviders(providers); renderVectors(vectors); renderCampaigns(campaigns); renderDecisions(decisions);
      await loadMap();
      document.getElementById('threatWorkspaceStatus').textContent = `Atualizado em ${new Date().toLocaleTimeString('pt-BR')}. Falhas externas permanecem isoladas do Threat Engine.`;
      root.lucide?.createIcons();
    } catch (error) {
      document.getElementById('threatWorkspaceStatus').textContent = `Falha ao atualizar: ${error.message}`;
      ensureMap()?.setError('Não foi possível carregar o mapa de Threat Intelligence.');
      throw error;
    } finally {
      loading = false;
    }
  }

  async function providerAction(button) {
    const provider = button.dataset.provider;
    const action = button.dataset.threatAction;
    button.disabled = true;
    try {
      if (action === 'toggle') {
        await apiRequest(`/api/threat-intelligence/providers/${encodeURIComponent(provider)}`, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: button.dataset.enabled !== 'true' })
        });
      } else {
        const result = await apiRequest(`/api/threat-intelligence/providers/${encodeURIComponent(provider)}/${action}`, { method: 'POST' });
        document.getElementById('threatWorkspaceStatus').textContent = `${provider}: ${result.status || (result.ok ? 'ONLINE' : 'falha')} ${result.error || ''}`;
      }
      await loadWorkspace();
    } finally {
      button.disabled = false;
    }
  }

  document.addEventListener('click', event => {
    const action = event.target.closest('[data-threat-action]');
    if (action) providerAction(action).catch(error => { document.getElementById('threatWorkspaceStatus').textContent = error.message; });
  });
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('refreshThreatWorkspaceButton')?.addEventListener('click', () => loadWorkspace().catch(console.error));
    document.getElementById('applyThreatFiltersButton')?.addEventListener('click', () => loadMap().catch(console.error));
    document.getElementById('runThreatEngineButton')?.addEventListener('click', async () => {
      const button = document.getElementById('runThreatEngineButton');
      button.disabled = true;
      try { await apiRequest('/api/threat-engine/run', { method: 'POST' }); await loadWorkspace(); }
      catch (error) { document.getElementById('threatWorkspaceStatus').textContent = error.message; }
      finally { button.disabled = false; }
    });
  });

  root.loadThreatIntelligenceWorkspace = loadWorkspace;
  root.threatDecisionSourceBadge = function (item) {
    const details = [item?.direction, item?.affected_customer,
      item?.threat_score !== null && item?.threat_score !== undefined ? `score ${number(item.threat_score)}` : '',
      item?.threat_confidence ? `conf. ${number(Number(item.threat_confidence) * 100, 1)}%` : '',
      item?.threat_hits ? `${number(item.threat_hits)} hits` : ''].filter(Boolean).join(' · ');
    return `<span class="d-inline-flex flex-wrap gap-1 mt-1">${sourceBadge(item?.decision_source)}${intelChips(item?.intel_sources)}</span>${details ? `<span class="subtle d-block mt-1">${esc(details)}</span>` : ''}`;
  };
}(typeof globalThis !== 'undefined' ? globalThis : window));
