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
    const status = String(value || 'WAITING_SYNC').toUpperCase();
    const css = status.toLowerCase().replace(/_/g, '-');
    return `<span class="threat-status-badge threat-status-${esc(css)}">${esc(status)}</span>`;
  }

  function providerStatusDescription(item) {
    const status = String(item?.status || 'WAITING_SYNC').toUpperCase();
    if (status === 'ACTIVE') return 'Dados válidos carregados e última coleta concluída.';
    if (status === 'WAITING_SYNC') return 'Aguardando a primeira coleta concluída.';
    if (status === 'DEGRADED') return `Última tentativa falhou; ${number(item?.item_count)} registros continuam utilizáveis.`;
    if (status === 'AUTH_ERROR') return 'A credencial do provider foi rejeitada ou não está configurada.';
    if (status === 'RATE_LIMITED') return `Limite do provider atingido; ${number(item?.item_count)} registros permanecem em uso.`;
    if (status === 'ERROR') return 'Última coleta falhou e não há dados utilizáveis.';
    return 'Provider desativado pelo usuário.';
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

  function intelMatchText(match) {
    const details = [match?.indicator_type, match?.classification,
      ...(Array.isArray(match?.tags) ? match.tags.slice(0, 3) : []), match?.botnet_family].filter(Boolean);
    return details.length ? details.join('/') : 'match';
  }

  function vectorIntelEvidence(item) {
    const threatIntel = item?.threat_intel || {};
    const sourceIntel = threatIntel.source_intel || {};
    const targetIntel = threatIntel.target_campaign_intel || {};
    const sourceRows = [];
    Object.entries(sourceIntel.sources || {}).slice(0, 6).forEach(([source, matches]) => {
      (Array.isArray(matches) ? matches : []).slice(0, 4).forEach(match => {
        sourceRows.push(`<div><code>${esc(source)}</code> ${sourceBadge(match.provider)} <span>${esc(intelMatchText(match))}</span></div>`);
      });
    });
    if (!sourceRows.length && Number(sourceIntel.matched_source_count || sourceIntel.matches || 0) > 0) {
      const summary = [
        ...(sourceIntel.indicator_types || []), ...(sourceIntel.classifications || []), ...(sourceIntel.tags || [])
      ].filter(Boolean).slice(0, 6).join('/');
      sourceRows.push(`<div>${intelChips(sourceIntel.intel_sources)} <span>${number(sourceIntel.matched_source_count || sourceIntel.matches)} origens${summary ? ` · ${esc(summary)}` : ''}</span></div>`);
    }
    const targetRows = (Array.isArray(targetIntel.observations) ? targetIntel.observations : []).slice(0, 3).map(observation =>
      `<div>${sourceBadge(observation.provider || 'EXTERNAL')} <span>${esc(observation.method || observation.protocol || 'campanha correlacionada')}</span></div>`
    );
    if (!targetRows.length && Number(targetIntel.matches || 0) > 0) {
      targetRows.push(`<div>${intelChips(targetIntel.intel_sources)} <span>${number(targetIntel.matches)} correlações</span></div>`);
    }
    return `<div class="threat-evidence-stack">
      <div class="threat-evidence-lane threat-evidence-local"><span class="threat-evidence-label">Detecção local</span>${sourceBadge('GMJ_FLOW')}</div>
      ${sourceRows.length ? `<div class="threat-evidence-lane threat-evidence-source"><span class="threat-evidence-label">Intel da origem</span>${sourceRows.join('')}</div>` : ''}
      ${targetRows.length ? `<div class="threat-evidence-lane threat-evidence-target"><span class="threat-evidence-label">Correlação alvo/campanha</span>${targetRows.join('')}</div>` : ''}
      ${!sourceRows.length && !targetRows.length ? '<span class="subtle">Sem enriquecimento externo</span>' : ''}
    </div>`;
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
        subtitle: 'Pontos agregados dos provedores externos; detalhes analíticos permanecem nas tabelas',
        mode: 'flows', metric: 'flows', groupBy: 'country', interactive: false,
        visualization: 'points', showControls: false, pointUnit: 'IPs',
        rankingLimit: 12, fitMaxZoom: 4
      });
    }
    return threatMap;
  }

  function classificationColor(value) {
    const classification = String(value || 'unknown').toLowerCase();
    if (classification === 'malicious' || classification === 'anomalous_source') return '#ef4444';
    if (classification === 'suspicious') return '#f59e0b';
    if (classification === 'c2') return '#a855f7';
    return '#38bdf8';
  }

  function topItems(items, fallbackName = '', fallbackCount = 0) {
    const normalized = Array.isArray(items) ? items.filter(item => item && (item.name || typeof item === 'string')) : [];
    if (normalized.length) return normalized.slice(0, 5).map(item => ({
      name: typeof item === 'string' ? item : item.name,
      count: typeof item === 'string' ? 0 : Number(item.count || 0)
    }));
    return fallbackName ? [{ name: fallbackName, count: Number(fallbackCount || 0) }] : [];
  }

  function popupList(items) {
    if (!items.length) return '<span class="subtle">Sem informação</span>';
    return items.map(item => `<span class="threat-map-popup__chip">${esc(item.name)}${item.count ? ` <strong>${number(item.count)}</strong>` : ''}</span>`).join('');
  }

  function pointPopup(item, ipCount) {
    const country = [item.city, item.country || item.country_code].filter(Boolean).join(', ') || item.country_code || 'Localização desconhecida';
    const organizations = topItems(item.top_organizations, item.organization, ipCount);
    const tags = topItems(item.top_tags);
    const providers = (Array.isArray(item.providers) ? item.providers : []).map(name => ({ name, count: 0 }));
    const classification = item.predominant_classification || item.classification || 'unknown';
    return `<div class="threat-map-popup">
      <div class="threat-map-popup__title">${esc(item.label || item.key || country)}</div>
      <dl><dt>País / localização</dt><dd>${esc(country)}</dd><dt>Quantidade de IPs</dt><dd><strong>${number(ipCount)}</strong></dd>
        <dt>Classificação predominante</dt><dd><span class="threat-map-classification" data-classification="${esc(String(classification).toLowerCase())}">${esc(classification)}</span></dd></dl>
      <div class="threat-map-popup__section"><strong>Top organizações</strong><div>${popupList(organizations)}</div></div>
      <div class="threat-map-popup__section"><strong>Top tags</strong><div>${popupList(tags)}</div></div>
      <div class="threat-map-popup__section"><strong>Providers envolvidos</strong><div>${popupList(providers)}</div></div>
    </div>`;
  }

  function stableLocationOffset(seed, index, grouped) {
    if (!grouped) return [0, 0];
    let hash = 2166136261;
    for (const character of String(seed || index)) {
      hash ^= character.charCodeAt(0);
      hash = Math.imul(hash, 16777619);
    }
    const angle = ((hash >>> 0) % 360) * (Math.PI / 180);
    const distance = 0.35 + (((hash >>> 8) % 100) / 100) * 1.15;
    return [Math.sin(angle) * distance, Math.cos(angle) * distance];
  }

  function mapNodes(items, groupBy) {
    return (items || []).map((item, index) => {
      const code = String(item.country_code || (String(item.key || '').length === 2 ? item.key : '')).toUpperCase();
      const center = COUNTRY_CENTERS[code];
      if (!center) return null;
      const ipCount = Number(item.unique_ips || item.count || 0);
      const offset = stableLocationOffset(item.key, index, groupBy !== 'country');
      return {
        id: `intel-${index}-${item.key || code}`,
        label: item.label || item.organization || item.key || code,
        lat: center[0] + offset[0], lon: center[1] + offset[1],
        value: ipCount,
        color: classificationColor(item.predominant_classification || item.classification),
        popup_html: pointPopup(item, ipCount)
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
        <div class="threat-provider-card__state">${esc(providerStatusDescription(item))}</div>
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
        <td>${esc(evidence)}</td><td>${vectorIntelEvidence(item)}</td>
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
      <td>${number(item.unique_sources)} / ${number(item.unique_source_asns)}</td><td>${vectorIntelEvidence(item)}</td>
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
      <td>${statusBadge(item.decision === 'ALLOW_AUTO' ? 'ACTIVE' : 'DISABLED')}<br><strong>${esc(item.decision)}</strong></td>
      <td>${esc(item.classification)}</td>
      <td><span class="threat-score ${scoreClass(item.policy_score)}">${number(item.policy_score)}</span><br><span class="subtle">Groq ${number(Number(item.confidence || 0) * 100, 1)}%</span></td>
      <td>${sourceBadge(item.decision_source)}<br>${intelChips(item.intel_sources)}</td>
      <td><code class="threat-flowspec">${esc(flowspecText(item.proposal))}</code></td>
      <td>${item.ttl_seconds ? `${number(item.ttl_seconds)} s` : '-'}</td>
      <td>${esc(item.reason || item.non_mitigation_reason || '-')}</td><td>${dateTime(item.created_at)}</td>
    </tr>`).join('') || '<tr><td colspan="8" class="text-muted">Nenhuma decisão registrada.</td></tr>';
  }

  async function loadMap() {
    const groupBy = document.getElementById('threatGroupFilter').value || 'country';
    const query = new URLSearchParams({ group_by: groupBy });
    const provider = document.getElementById('threatProviderFilter').value;
    const classification = document.getElementById('threatClassificationFilter').value.trim();
    const tag = document.getElementById('threatTagFilter').value.trim();
    if (provider) query.set('provider', provider);
    if (classification) query.set('classification', classification);
    if (tag) query.set('tag', tag);
    const map = ensureMap();
    map?.setLoading('Carregando indicadores geográficos...');
    const payload = await apiRequest(`/api/threat-intelligence/map?${query}`);
    map?.setData(
      { nodes: mapNodes(payload.items, payload.group_by || groupBy), metric: 'flows', group_by: payload.group_by || groupBy },
      { metric: 'flows', mode: 'flows', visualization: 'points', groupBy: payload.group_by || groupBy, fit: true }
    );
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
        document.getElementById('threatWorkspaceStatus').textContent = `${provider}: ${result.status || (result.ok ? 'ACTIVE' : 'falha')} ${result.error || ''}`;
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
    const structuredIntel = item?.threat_intel?.source_intel || item?.threat_intel?.target_campaign_intel
      ? vectorIntelEvidence(item) : '';
    return `<span class="d-inline-flex flex-wrap gap-1 mt-1">${sourceBadge(item?.decision_source)}${intelChips(item?.intel_sources)}</span>${details ? `<span class="subtle d-block mt-1">${esc(details)}</span>` : ''}${structuredIntel}`;
  };
}(typeof globalThis !== 'undefined' ? globalThis : window));
