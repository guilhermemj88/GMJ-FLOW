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
  let currentSecurityEventId = null;

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
    document.getElementById('threatSummaryVectors').textContent = number(payload.total ?? items.length);
    document.getElementById('threatVectorRows').innerHTML = items.map(item => {
      const features = item.features || {};
      const confidence = Number(item.confidence || 0);
      const sourceIntel = item.threat_intel?.source_intel || {};
      const evidence = [
        item.packets_per_second ? `${number(item.packets_per_second, 1)} pps` : '',
        item.unique_sources ? `${number(item.unique_sources)} fontes` : '',
        item.unique_destinations ? `${number(item.unique_destinations)} destinos` : '',
        item.recurrence_count ? `${number(item.recurrence_count)} ocorrências` : ''
      ].filter(Boolean).join(' · ') || '-';
      return `<tr class="security-event-row" tabindex="0" data-security-event-id="${number(item.id)}" title="Abrir investigação">
        <td><strong>${esc(item.attack_type)}</strong><br><span class="subtle">${esc(item.attack_family || '-')} · ${esc(item.severity || '-')}</span></td>
        <td>${esc(item.src_ip || 'distribuída')} → ${esc(item.target_prefix || item.target_ip || '-')}</td>
        <td><span class="threat-score ${scoreClass(item.detector_score)}">${number(item.detector_score)}</span><br><span class="subtle">${esc(item.verdict || 'INFO')} · conf. ${number(confidence <= 1 ? confidence * 100 : confidence, 1)}%</span></td>
        <td><span class="subtle">${esc(item.direction || 'UNKNOWN')} · ${esc(item.src_role || 'UNKNOWN')} → ${esc(item.dst_role || 'UNKNOWN')}</span><br>${esc(evidence)}</td>
        <td>${vectorIntelEvidence(item)}<div class="subtle">${number(sourceIntel.matched_source_count || sourceIntel.matches)} / ${number(sourceIntel.lookup_count)} origens</div></td>
        <td>${item.ai_analysis?.verdict ? `<strong>${esc(item.ai_analysis.verdict)}</strong><br><span class="subtle">${number(item.ai_analysis.confidence, 1)}%</span>` : '<span class="subtle">Não analisado</span>'}</td>
        <td>${dateTime(item.last_seen)}<br><button type="button" class="btn btn-sm btn-outline-secondary mt-1" data-security-action="open" data-event-id="${number(item.id)}">Ver detalhes</button></td>
      </tr>`;
    }).join('') || '<tr><td colspan="7" class="text-muted">Nenhum evento comportamental recente.</td></tr>';
  }

  function renderCampaigns(payload) {
    const items = payload.items || [];
    document.getElementById('threatSummaryCampaigns').textContent = number(items.length);
    document.getElementById('threatCampaignRows').innerHTML = items.map(item => `<tr class="security-event-row" tabindex="0" data-security-campaign-id="${esc(item.campaign_id)}">
      <td><code>${esc(item.campaign_id)}</code><br><span class="subtle">${dateTime(item.last_seen)}</span></td>
      <td><strong>${esc(item.classification)}</strong><br>${esc(item.target_prefix || '-')}</td>
      <td><span class="threat-score ${scoreClass(item.coordination_score)}">${number(item.coordination_score)}</span><br><span class="subtle">${number(item.packets_per_second, 1)} pps</span></td>
      <td>${number(item.unique_sources)} / ${number(item.unique_source_asns)}</td><td>${vectorIntelEvidence(item)}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="text-muted">Nenhum Campaign Vector recente.</td></tr>';
  }

  function detailGrid(entries) {
    return `<dl class="security-event-detail-grid">${entries.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${value === null || value === undefined || value === '' ? '-' : esc(value)}</dd></div>`).join('')}</dl>`;
  }

  function evidenceList(values) {
    const items = Array.isArray(values) ? values : [];
    return items.length ? `<ul>${items.map(item => `<li>${esc(item)}</li>`).join('')}</ul>` : '<div class="subtle">Sem evidências registradas.</div>';
  }

  function renderAiAnalysis(event) {
    const analysis = event.ai_analysis || {};
    if (!analysis.verdict) {
      return `<div class="subtle">Este evento ainda não foi analisado por IA.</div>
        <button type="button" class="btn btn-sm btn-success mt-2" data-security-action="analyze" data-event-id="${number(event.id)}">ANALISAR COM IA</button>`;
    }
    return `<div class="security-ai-verdict"><strong>${esc(analysis.verdict)}</strong><span>${number(analysis.confidence, 1)}%</span></div>
      <p>${esc(analysis.summary || '')}</p>
      <h4>Evidências a favor de ataque</h4>${evidenceList(analysis.evidence_for_attack)}
      <h4>Evidências contra ataque</h4>${evidenceList(analysis.evidence_against_attack)}
      ${detailGrid([
        ['Explicação provável', analysis.likely_explanation],
        ['Contexto de rede', analysis.network_context_interpretation],
        ['Threat Intelligence', analysis.threat_intel_interpretation],
        ['Ação recomendada', analysis.recommended_action],
        ['Mitigação recomendada', analysis.mitigation_recommended ? 'Sim — requer Policy Engine' : 'Não']
      ])}
      <div class="subtle">${esc(event.ai_provider || '-')} · ${esc(event.ai_model || '-')} · ${esc(event.analysis_version || '-')} · ${dateTime(event.analyzed_at)}</div>
      <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-security-action="reanalyze" data-event-id="${number(event.id)}">REANALISAR</button>`;
  }

  function renderThreatIntelDetail(event) {
    const intel = event.threat_intel || {};
    const source = intel.source_intel || {};
    const sourceRows = Object.entries(source.sources || {}).flatMap(([ip, matches]) =>
      (Array.isArray(matches) ? matches : []).map(match => `<tr><td><code>${esc(ip)}</code></td><td>${esc(match.provider || '-')}</td><td>${esc(match.classification || match.indicator_type || '-')}</td><td>${esc((match.tags || []).join(', ') || '-')}</td></tr>`)
    );
    return `<p><strong>${number(source.matched_source_count || source.matches)} de ${number(source.lookup_count)} origens consultadas</strong> possuem histórico em Threat Intelligence${source.lookup_truncated ? ' (consulta truncada)' : ''}.</p>
      <p class="subtle">Reputação histórica enriquece a detecção local; não confirma que o tráfego atual use o mesmo protocolo ou represente o mesmo vetor.</p>
      ${sourceRows.length ? `<div class="table-wrap"><table class="table table-sm"><thead><tr><th>IP</th><th>Provider</th><th>Classificação</th><th>Tags</th></tr></thead><tbody>${sourceRows.join('')}</tbody></table></div>` : '<div class="subtle">Nenhum match externo.</div>'}`;
  }

  function renderSecurityEventDetail(event, related = []) {
    const evidence = event.evidence || {};
    const network = event.network_context || {};
    const components = event.score_components || {};
    const duration = Math.max(0, (new Date(event.last_seen).getTime() - new Date(event.first_seen).getTime()) / 1000);
    document.getElementById('securityEventDrawerTitle').textContent = `${event.attack_type} #${event.id}`;
    document.getElementById('securityEventDrawerBody').innerHTML = `
      <section><h3>Resumo</h3>${detailGrid([
        ['Família', event.attack_family], ['Severity / verdict', `${event.severity} / ${event.verdict}`],
        ['Score / confiança', `${number(event.detector_score)} / ${number(event.confidence, 1)}%`],
        ['Direção', event.direction], ['Origem → alvo', `${event.src_ip || 'distribuída'} → ${event.target_prefix || event.target_ip || '-'}`],
        ['Primeira / última', `${dateTime(event.first_seen)} / ${dateTime(event.last_seen)}`],
        ['Duração / recorrência', `${number(duration, 0)} s / ${number(event.recurrence_count)}`], ['Status', event.status]
      ])}</section>
      <section><h3>Network Context</h3>${detailGrid([
        ['Papéis', `${event.src_role} → ${event.dst_role}`], ['CGNAT', event.cgnat_context || 'não'],
        ['Prefixos', `${event.src_prefix || '-'} → ${event.target_prefix || network.dst_prefix || '-'}`],
        ['Interfaces', `in ${event.input_if || '-'} / out ${event.output_if || '-'}`], ['Sensor / exporter', `${event.sensor || '-'} / ${event.exporter || '-'}`]
      ])}</section>
      <section><h3>Tráfego</h3>${detailGrid([
        ['Protocolo', event.protocol], ['Pacotes / pps', `${number(event.packets)} / ${number(event.packets_per_second, 2)}`],
        ['bit/s', number(event.bits_per_second, 1)], ['Flows / flows/s', `${number(event.flows)} / ${number(event.flows_per_second, 2)}`],
        ['Fontes / destinos', `${number(event.unique_sources)} / ${number(event.unique_destinations)}`],
        ['Portas src / dst', `${number(event.unique_src_ports)} / ${number(event.unique_dst_ports)}`],
        ['ASNs de origem', number(event.unique_source_asns)], ['Baseline', `${number(event.baseline_deviation, 2)}x`]
      ])}</section>
      <section><h3>Evidências do detector</h3>${evidenceList(evidence.facts)}
        <h4>Composição do score</h4>${detailGrid(Object.entries(components))}</section>
      <section><h3>Threat Intelligence</h3>${renderThreatIntelDetail(event)}</section>
      <section><h3>Análise por IA</h3>${renderAiAnalysis(event)}</section>
      <section><h3>Eventos relacionados</h3>${related.length ? evidenceList(related.map(item => `#${item.id} ${item.attack_type} · ${item.verdict} · ${dateTime(item.last_seen)}`)) : '<div class="subtle">Nenhum evento relacionado.</div>'}</section>
      <footer class="security-event-review-actions">
        <button type="button" class="btn btn-sm btn-outline-secondary" data-security-action="status" data-status="investigating" data-event-id="${number(event.id)}">Investigando</button>
        <button type="button" class="btn btn-sm btn-outline-success" data-security-action="status" data-status="benign" data-event-id="${number(event.id)}">Marcar benigno</button>
        <button type="button" class="btn btn-sm btn-outline-danger" data-security-action="status" data-status="confirmed" data-event-id="${number(event.id)}">Confirmar ataque</button>
      </footer>`;
    root.lucide?.createIcons();
  }

  async function openSecurityEvent(eventId) {
    currentSecurityEventId = Number(eventId);
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('security-event-drawer-open');
    document.getElementById('securityEventDrawerStatus').textContent = 'Carregando evidências...';
    const [event, related] = await Promise.all([
      apiRequest(`/security/events/${currentSecurityEventId}`),
      apiRequest(`/security/events/${currentSecurityEventId}/related?limit=20`)
    ]);
    document.getElementById('securityEventDrawerStatus').textContent = '';
    renderSecurityEventDetail(event, related.items || []);
  }

  async function openSecurityCampaign(campaignId) {
    currentSecurityEventId = null;
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('security-event-drawer-open');
    document.getElementById('securityEventDrawerStatus').textContent = 'Carregando campanha...';
    const payload = await apiRequest(`/security/campaigns/${encodeURIComponent(campaignId)}`);
    const campaign = payload.campaign || {};
    document.getElementById('securityEventDrawerTitle').textContent = `Campanha ${campaign.campaign_id || campaignId}`;
    document.getElementById('securityEventDrawerStatus').textContent = '';
    document.getElementById('securityEventDrawerBody').innerHTML = `
      <section><h3>Resumo da campanha</h3>${detailGrid([
        ['Classificação', campaign.classification], ['Alvo', campaign.target_prefix],
        ['Score de coordenação', campaign.coordination_score], ['Fontes / ASNs', `${number(campaign.unique_sources)} / ${number(campaign.unique_source_asns)}`],
        ['pps / bit/s', `${number(campaign.packets_per_second, 2)} / ${number(campaign.bits_per_second, 1)}`],
        ['Primeira / última', `${dateTime(campaign.first_seen)} / ${dateTime(campaign.last_seen)}`],
        ['Família', campaign.features?.attack_family], ['Persistência', campaign.features?.persistence_satisfied ? 'satisfeita' : 'insuficiente']
      ])}</section>
      <section><h3>Vetores correlacionados</h3>${(payload.events || []).length ? (payload.events || []).map(item => `
        <button type="button" class="security-related-event" data-security-action="open" data-event-id="${number(item.id)}">
          <strong>${esc(item.attack_type)}</strong><span>${esc(item.verdict)} · ${number(item.packets_per_second, 1)} pps · ${dateTime(item.last_seen)}</span>
        </button>`).join('') : '<div class="subtle">Nenhum evento canônico vinculado.</div>'}</section>`;
  }

  function renderLegacySecurityAnomalyDetail(item) {
    const available = entries => entries.filter(([, value]) => value !== null && value !== undefined && value !== '');
    const anomalyId = number(item.id);
    const mitigationId = number(item._mitigation_anomaly_id || item.id);
    document.getElementById('securityEventDrawerTitle').textContent = `Legacy anomaly #${anomalyId}`;
    document.getElementById('securityEventDrawerStatus').textContent = 'Legacy anomaly';
    document.getElementById('securityEventDrawerBody').innerHTML = `
      <section><h3>Legacy anomaly</h3>${detailGrid(available([
        ['Status', item.status], ['Severidade', item.severity], ['Zona', item.zone_name],
        ['Prefixo', item.prefix_cidr], ['Vetor', item.vector], ['Origem', item.src_ip],
        ['Destino', item.dst_ip], ['Porta destino', item.dst_port], ['Protocolo', item.protocol],
        ['pps', item.packets_s], ['bit/s', item.bits_s], ['Fluxos/s', item.flows_s],
        ['Fluxos', item.flows], ['Resposta', item.response], ['Última ocorrência', item.last_seen]
      ]))}</section>
      ${item.message ? `<section><h3>Evidência disponível</h3><p>${esc(item.message)}</p></section>` : ''}
      ${item.recommended_action ? `<section><h3>Ação recomendada</h3><p>${esc(item.recommended_action)}</p></section>` : ''}
      <footer class="security-event-review-actions">
        <button type="button" class="btn btn-sm btn-outline-success" data-legacy-security-action="mitigate" data-anomaly-id="${mitigationId}">Mitigar</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-legacy-security-action="ack" data-anomaly-id="${anomalyId}">Ack</button>
        <button type="button" class="btn btn-sm btn-outline-danger" data-legacy-security-action="close" data-anomaly-id="${anomalyId}">Close</button>
      </footer>`;
    root.lucide?.createIcons();
  }

  function openLegacySecurityAnomaly(item) {
    if (!item) return;
    currentSecurityEventId = null;
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('security-event-drawer-open');
    renderLegacySecurityAnomalyDetail(item);
  }

  async function legacySecurityAction(button) {
    const action = button.dataset.legacySecurityAction;
    const anomalyId = Number(button.dataset.anomalyId);
    if (action === 'mitigate') {
      await root.openBgpMitigationModal?.(anomalyId);
      return;
    }
    if (action === 'ack' || action === 'close') {
      await apiRequest(`/api/security/anomalies/${anomalyId}/${action}`, { method: 'POST' });
      closeSecurityEvent();
      await root.loadSecurityAnomaliesForAnomalyView?.();
    }
  }

  function closeSecurityEvent() {
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = true;
    drawer.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('security-event-drawer-open');
    currentSecurityEventId = null;
  }

  async function securityAction(button) {
    const action = button.dataset.securityAction;
    if (action === 'close') return closeSecurityEvent();
    const eventId = Number(button.dataset.eventId || currentSecurityEventId);
    if (action === 'open') return openSecurityEvent(eventId);
    button.disabled = true;
    try {
      if (action === 'analyze' || action === 'reanalyze') {
        const endpoint = action === 'reanalyze' ? 'reanalyze-ai' : 'analyze-ai';
        document.getElementById('securityEventDrawerStatus').textContent = 'Analisando evidências estruturadas...';
        await apiRequest(`/security/events/${eventId}/${endpoint}`, { method: 'POST' });
      } else if (action === 'status') {
        const endpoints = { benign: 'mark-benign', confirmed: 'mark-confirmed', investigating: 'investigating' };
        await apiRequest(`/security/events/${eventId}/${endpoints[button.dataset.status]}`, { method: 'POST' });
      }
      await openSecurityEvent(eventId);
      await loadWorkspace();
    } finally {
      button.disabled = false;
    }
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
        apiRequest('/api/threat-intelligence/providers'), apiRequest('/security/events?limit=200'),
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
    const legacyAction = event.target.closest('[data-legacy-security-action]');
    if (legacyAction) {
      event.stopPropagation();
      legacySecurityAction(legacyAction).catch(error => { document.getElementById('securityEventDrawerStatus').textContent = error.message; });
      return;
    }
    const security = event.target.closest('[data-security-action]');
    if (security) {
      event.stopPropagation();
      securityAction(security).catch(error => { document.getElementById('securityEventDrawerStatus').textContent = error.message; });
      return;
    }
    const row = event.target.closest('[data-security-event-id]');
    if (row) {
      openSecurityEvent(row.dataset.securityEventId).catch(error => { document.getElementById('threatWorkspaceStatus').textContent = error.message; });
      return;
    }
    const campaignRow = event.target.closest('[data-security-campaign-id]');
    if (campaignRow) {
      openSecurityCampaign(campaignRow.dataset.securityCampaignId).catch(error => { document.getElementById('threatWorkspaceStatus').textContent = error.message; });
      return;
    }
    const legacyRow = event.target.closest('[data-legacy-security-anomaly-id]');
    if (legacyRow) {
      const item = root.gmjLegacySecurityAnomalyCache?.get(String(legacyRow.dataset.legacySecurityAnomalyId));
      openLegacySecurityAnomaly(item);
      return;
    }
    const action = event.target.closest('[data-threat-action]');
    if (action) providerAction(action).catch(error => { document.getElementById('threatWorkspaceStatus').textContent = error.message; });
  });
  document.addEventListener('DOMContentLoaded', () => {
    document.addEventListener('keydown', event => { if (event.key === 'Escape' && !document.getElementById('securityEventDrawer')?.hidden) closeSecurityEvent(); });
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
  root.openSecurityEventInvestigation = eventId => openSecurityEvent(eventId).catch(error => {
    const status = document.getElementById('threatWorkspaceStatus') || document.getElementById('anomalyStatus');
    if (status) status.textContent = error.message;
  });
  root.openLegacySecurityAnomalyInvestigation = openLegacySecurityAnomaly;
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
