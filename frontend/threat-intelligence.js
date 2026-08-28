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
  let currentSecurityCampaignId = null;
  let currentSecurityEvent = null;
  let currentSecuritySources = [];
  let securityTrafficChart = null;
  let securityEventsRequestPromise = null;
  let securityEventsPollingTimer = null;
  let securityEventsPollingSeconds = 10;

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  function number(value, digits = 0) {
    const parsed = Number(value || 0);
    return Number.isFinite(parsed) ? parsed.toLocaleString('pt-BR', { maximumFractionDigits: digits }) : '0';
  }

  function optionalNumber(value, digits = 0, suffix = '') {
    if (value === null || value === undefined || value === '') return '-';
    return `${number(value, digits)}${suffix}`;
  }

  function rateNumber(value) {
    const parsed = Number(value);
    return number(value, Number.isFinite(parsed) && Math.abs(parsed) < 1 ? 3 : 1);
  }

  function setPanelStatus(elementId, message = '', isError = false) {
    const element = document.getElementById(elementId);
    if (!element) return;
    element.textContent = message;
    element.classList.toggle('text-danger', Boolean(isError));
  }

  function localizedLevel(value) {
    return ({ low: 'Baixa', medium: 'Média', high: 'Alta' })[String(value || '').toLowerCase()] || '-';
  }

  function localizedRisk(value) {
    return ({ low: 'Baixo', medium: 'Médio', high: 'Alto' })[String(value || '').toLowerCase()] || '-';
  }

  function scannerTargetLabel(item) {
    const target = item.target_prefix || item.target_ip;
    if (target) return target;
    const features = item.features || {};
    const destinations = Number(item.unique_destinations ?? features.unique_destinations ?? features.unique_dst_ips ?? 0);
    const ports = Number(item.unique_dst_ports ?? features.unique_dst_ports ?? 0);
    const scannerTypes = new Set(['PORT_SCAN_HORIZONTAL', 'NETWORK_SWEEP', 'LOW_SLOW_SCAN']);
    if (scannerTypes.has(String(item.attack_type || '').toUpperCase()) && destinations > 0) {
      return `múltiplos destinos (${number(destinations)})${ports > 1 ? ` / ${number(ports)} portas` : ''}`;
    }
    return destinations > 1 ? `múltiplos destinos (${number(destinations)})` : '-';
  }

  function scannerIntelBadges(item) {
    const sourceIntel = item.threat_intel?.source_intel || {};
    const serialized = JSON.stringify(sourceIntel).toLowerCase();
    const labels = [];
    if (Number(sourceIntel.scanner_sources || 0) > 0 || serialized.includes('scanner') || serialized.includes('scan')) labels.push('Scanner conhecido');
    if (Number(sourceIntel.malicious_sources || 0) > 0 || serialized.includes('malicious')) labels.push('Malicious');
    if (serialized.includes('greynoise')) labels.push('GreyNoise');
    if (serialized.includes('botnet')) labels.push('Botnet');
    if (serialized.includes('exploit')) labels.push('Exploit');
    if (serialized.includes('ssh') && (serialized.includes('brute') || serialized.includes('scanner'))) labels.push('SSH brute force');
    return labels.length ? `<div class="mt-1">${[...new Set(labels)].map(label => `<span class="threat-intel-chip">${esc(label)}</span>`).join('')}</div>` : '';
  }

  function dateTime(value) {
    if (!value) return '-';
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? esc(value) : parsed.toLocaleString('pt-BR');
  }

  function humanDuration(value) {
    const total = Number(value);
    if (!Number.isFinite(total) || total < 0) return '-';
    const seconds = Math.floor(total);
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainder = seconds % 60;
    return [hours ? `${hours}h` : '', (minutes || hours) ? `${String(minutes).padStart(2, '0')}m` : '',
      `${String(remainder).padStart(2, '0')}s`].filter(Boolean).join(' ');
  }

  function setInvestigationHeading(context, title) {
    const label = document.getElementById('securityEventDrawerContext');
    if (label) label.textContent = context;
    document.getElementById('securityEventDrawerTitle').textContent = title;
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
        title: 'Mapa de situação de segurança',
        subtitle: '',
        mode: 'flows', metric: 'flows', groupBy: 'country', interactive: false,
        visualization: 'points', showControls: false, pointUnit: 'eventos',
        rankingLimit: 12, fitMaxZoom: 4, rankingMetaLabel: 'Ameaça detectada'
      });
    }
    return threatMap;
  }

  function setMapMeta(title, subtitle, metaLabel, pointUnit) {
    const map = ensureMap();
    if (!map) return;
    if (metaLabel) map.options.rankingMetaLabel = metaLabel;
    if (pointUnit) map.options.pointUnit = pointUnit;
    const titleElement = map.element?.querySelector('.geo-flow-map__title');
    const subtitleElement = map.element?.querySelector('.geo-flow-map__subtitle');
    if (titleElement) titleElement.textContent = title;
    if (subtitleElement) subtitleElement.textContent = subtitle;
  }

  const SECURITY_TIER_STYLE = {
    critical: '#ef4444',
    elevated: '#f97316',
    suspicious: '#facc15',
    info: '#818cf8',
    benign: '#64748b'
  };

  const SECURITY_TIER_LABEL = {
    critical: 'Confirmado / Crítico',
    elevated: 'Provável / Alto',
    suspicious: 'Suspeito',
    info: 'Informativo',
    benign: 'Resolvido / Benigno'
  };

  function securityMapSeverityStyle(tier) {
    return SECURITY_TIER_STYLE[String(tier || 'info').toLowerCase()] || SECURITY_TIER_STYLE.info;
  }

  function securityTierLabel(tier) {
    return SECURITY_TIER_LABEL[String(tier || 'info').toLowerCase()] || SECURITY_TIER_LABEL.info;
  }

  function securityMapPopup(point) {
    const location = [point.city, point.country || point.country_code].filter(Boolean).join(', ') || point.country_code || 'Localização desconhecida';
    const attackTypes = (Array.isArray(point.top_attack_types) ? point.top_attack_types : []).map(type =>
      `<span class="threat-map-popup__chip">${esc(type)}</span>`).join('') || '<span class="subtle">Sem informação</span>';
    const subject = point.predominant_geo_subject === 'destination' ? 'Destino externo observado' : point.predominant_geo_subject === 'source' ? 'Origem observada' : '-';
    const directionLabel = ({ INBOUND: 'Inbound', OUTBOUND: 'Outbound', INTERNAL: 'Internal' })[point.predominant_direction] || point.predominant_direction || '-';
    const geoSourceLabel = ({ MAXMIND_CITY: 'GeoIP: cidade/país', COUNTRY_CENTROID: 'País aproximado (centroid)', ASN_COUNTRY: 'País via ASN' })[point.geo_source] || '-';
    const analysis = [
      point.analyzed_count ? `${number(point.analyzed_count)} analisado(s)` : '',
      point.not_analyzed_count ? `${number(point.not_analyzed_count)} não analisado(s)` : ''
    ].filter(Boolean).join(' · ') || '-';
    const campaignInfo = point.campaign_count ? `${number(point.campaign_count)}${point.top_campaign ? ` · principal: ${esc(point.top_campaign)}` : ''}` : '-';
    return `<div class="threat-map-popup">
      <div class="threat-map-popup__title">${esc(point.label || point.key || location)}</div>
      <div class="threat-map-popup__badge"><span class="threat-map-tier" style="--tier-color:${esc(point.color || securityMapSeverityStyle(point.tier))}">${esc(securityTierLabel(point.tier))}</span></div>
      <dl>
        <dt>Geografia</dt><dd>${esc(subject)}</dd>
        <dt>Direção</dt><dd>${esc(directionLabel)}</dd>
        <dt>Precisão</dt><dd>${esc(geoSourceLabel)}</dd>
        <dt>Eventos</dt><dd><strong>${number(point.event_count)}</strong> (${number(point.critical_count)} crítico${point.critical_count === 1 ? '' : 's'} · ${number(point.high_count)} alto · ${number(point.warning_count)} alerta)</dd>
        <dt>Confirmados / Prováveis</dt><dd>${number(point.confirmed_count)} / ${number(point.likely_count)}</dd>
        <dt>Threat Score máx.</dt><dd>${number(point.max_threat_score)}</dd>
        <dt>Campaign Risk máx.</dt><dd>${number(point.max_campaign_risk_score)}</dd>
        <dt>Campanhas</dt><dd>${esc(campaignInfo)}</dd>
        <dt>Análise</dt><dd>${esc(analysis)}</dd>
        <dt>Primeira / última ocorrência</dt><dd>${dateTime(point.first_seen)} / ${dateTime(point.latest_seen)}</dd>
      </dl>
      <div class="threat-map-popup__section"><strong>Tipos de ataque</strong><div>${attackTypes}</div></div>
    </div>`;
  }

  function securityMapNodes(points) {
    return (points || []).map((point, index) => {
      const criticalPart = point.critical_count ? `${number(point.critical_count)} crítico${point.critical_count === 1 ? '' : 's'}` : '';
      const threatPart = point.max_threat_score ? `Threat ${number(point.max_threat_score)}` : '';
      const riskPart = point.max_campaign_risk_score > 0 ? `Risk ${number(point.max_campaign_risk_score)}` : '';
      const rankingSub = [criticalPart, threatPart, riskPart].filter(Boolean).join(' · ');
      return {
        id: `sec-${index}-${point.key || point.label}`,
        label: point.label || point.key,
        lat: point.lat,
        lon: point.lon,
        value: Number(point.event_count || 0),
        color: point.color || securityMapSeverityStyle(point.tier),
        popup_html: securityMapPopup(point),
        ranking_sub: rankingSub,
        ranking_value: `${number(point.event_count)} evento${point.event_count === 1 ? '' : 's'}`
      };
    }).filter(node => node.lat !== null && node.lon !== null && node.lat !== undefined && node.lon !== undefined);
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
        item.packets_per_second ? `${rateNumber(item.packets_per_second)} pps` : '',
        item.unique_sources ? `${number(item.unique_sources)} fontes` : '',
        item.unique_destinations ? `${number(item.unique_destinations)} destinos` : '',
        item.unique_dst_ports ? `${number(item.unique_dst_ports)} portas` : '',
        item.recurrence_count ? `${number(item.recurrence_count)} ocorrências` : ''
      ].filter(Boolean).join(' · ') || '-';
      return `<tr class="security-event-row" tabindex="0" data-security-event-id="${item.id}" title="Abrir investigação">
        <td><strong>${esc(item.attack_type)}</strong><br><code>${esc(item.event_id || `#${item.id}`)}</code><br><span class="subtle">${esc(item.attack_family || '-')} · ${esc(item.severity || '-')}</span></td>
        <td>${esc(item.src_ip || 'distribuída')} → ${esc(scannerTargetLabel(item))}</td>
        <td><span class="threat-score ${scoreClass(item.detector_score)}">${number(item.detector_score)}</span><br><span class="subtle">${esc(item.verdict || 'INFO')} · conf. ${number(confidence <= 1 ? confidence * 100 : confidence, 1)}%</span></td>
        <td><span class="subtle">${esc(item.direction || 'UNKNOWN')} · ${esc(item.src_role || 'UNKNOWN')} → ${esc(item.dst_role || 'UNKNOWN')}</span><br>${esc(evidence)}</td>
        <td>${vectorIntelEvidence(item)}${scannerIntelBadges(item)}<div class="subtle">${number(sourceIntel.matched_source_count || sourceIntel.matches)} / ${number(sourceIntel.lookup_count)} origens</div></td>
        <td>${item.ai_analysis?.verdict ? `<strong>${esc(item.ai_analysis.verdict)}</strong><br><span class="subtle">${number(item.ai_analysis.confidence, 1)}%</span>` : '<span class="subtle">Não analisado</span>'}</td>
        <td>${dateTime(item.last_seen)}<br><button type="button" class="btn btn-sm btn-outline-secondary mt-1" data-security-action="open" data-event-id="${item.id}">Ver detalhes</button></td>
      </tr>`;
    }).join('') || '<tr><td colspan="7" class="text-muted">Nenhum evento comportamental recente.</td></tr>';
  }

  function renderCampaigns(payload) {
    const items = payload.items || [];
    document.getElementById('threatSummaryCampaigns').textContent = number(items.length);
    document.getElementById('threatCampaignRows').innerHTML = items.map(item => {
      const evaluation = item.context_evaluation || {};
      const role = evaluation.context?.target_role || item.features?.target_role || 'UNKNOWN';
      return `<tr class="security-event-row" tabindex="0" data-security-campaign-id="${esc(item.campaign_id)}">
      <td><code>${esc(item.campaign_id)}</code><br><span class="subtle">${dateTime(item.last_seen)}</span></td>
      <td><strong>${esc(item.classification)}</strong><br>${esc(item.target_prefix || '-')}<br><span class="subtle">Role: ${esc(role)}</span></td>
      <td><span class="threat-score ${scoreClass(item.coordination_score)}">${number(item.coordination_score)}</span><br><span class="subtle">Score comportamental · ${number(item.packets_per_second, 1)} pps</span><br>
        <strong>Estado: ${esc(String(evaluation.state || '-').toUpperCase())}</strong><br><span class="subtle">Confiança: ${esc(localizedLevel(evaluation.attack_confidence))} · Risco FP: ${esc(localizedRisk(evaluation.false_positive_risk))}</span>${renderCampaignRiskBadge(item)}</td>
      <td>${number(item.unique_sources)} / ${number(item.unique_source_asns)}</td><td>${vectorIntelEvidence(item)}</td>
    </tr>`;
    }).join('') || '<tr><td colspan="5" class="text-muted">Nenhum Campaign Vector recente.</td></tr>';
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
        <button type="button" class="btn btn-sm btn-success mt-2" data-security-action="analyze" data-event-id="${event.id}">ANALISAR COM IA</button>`;
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
      <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-security-action="reanalyze" data-event-id="${event.id}">REANALISAR</button>`;
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
    setInvestigationHeading('Security Event Investigation', `${event.attack_type} #${event.id}`);
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
        <button type="button" class="btn btn-sm btn-outline-secondary" data-security-action="status" data-status="investigating" data-event-id="${event.id}">Investigando</button>
        <button type="button" class="btn btn-sm btn-outline-success" data-security-action="status" data-status="benign" data-event-id="${event.id}">Marcar benigno</button>
        <button type="button" class="btn btn-sm btn-outline-danger" data-security-action="status" data-status="confirmed" data-event-id="${event.id}">Confirmar ataque</button>
      </footer>`;
    root.lucide?.createIcons();
  }

  async function openSecurityEvent(eventId) {
    currentSecurityCampaignId = null;
    currentSecurityEventId = Number(eventId);
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('security-event-drawer-open');
    document.getElementById('securityEventDrawerStatus').textContent = 'Carregando evidências...';
    const [event, related] = await Promise.all([
      apiRequest(`/api/security/events/${currentSecurityEventId}`),
      apiRequest(`/api/security/events/${currentSecurityEventId}/related?limit=20`)
    ]);
    document.getElementById('securityEventDrawerStatus').textContent = '';
    renderSecurityEventDetail(event, related.items || []);
  }

  function securityBytes(value) {
    const amount = Number(value || 0);
    if (!Number.isFinite(amount) || amount <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const index = Math.min(Math.floor(Math.log(amount) / Math.log(1024)), units.length - 1);
    return `${number(amount / (1024 ** index), 2)} ${units[index]}`;
  }

  function canManageSecurityEvents() {
    return typeof root.hasPermission !== 'function' || root.hasPermission('anomalies.manage');
  }

  function investigationList(values, empty = 'Sem dados registrados.') {
    const items = Array.isArray(values) ? values : [];
    return items.length
      ? `<ul>${items.map(item => `<li>${esc(typeof item === 'string' ? item : JSON.stringify(item))}</li>`).join('')}</ul>`
      : `<div class="subtle">${esc(empty)}</div>`;
  }

  function renderSecurityAiInvestigation(event, state = {}) {
    const analysis = state.analysis && Object.keys(state.analysis).length ? state.analysis : (event.ai_analysis || {});
    const hasAnalysis = Object.keys(analysis).length > 0;
    const inherited = state.analysis_source === 'campaign' && state.inherited_from_campaign === true;
    const canAnalyze = canManageSecurityEvents() && state.enabled === true && state.configured === true;
    const unavailable = !state.enabled
      ? 'Security AI desabilitada por configuração.'
      : !state.configured
        ? 'Provider, modelo ou credencial não configurados no backend.'
        : !canManageSecurityEvents() ? 'Seu perfil não pode solicitar análise.' : '';
    if (!hasAnalysis) {
      return `<p class="subtle">Ainda não analisado. A execução ocorre somente mediante clique e é consultiva.</p>
        ${state.error ? `<div class="security-ai-error">${esc(state.error)}</div>` : ''}
        <button type="button" class="btn btn-sm btn-success mt-2" data-security-action="analyze" data-event-id="${event.id}" ${canAnalyze ? '' : 'disabled'}>ANALISAR COM IA</button>
        ${unavailable ? `<div class="subtle mt-1">${esc(unavailable)}</div>` : ''}`;
    }
    const confidence = typeof analysis.confidence === 'number' ? `${number(analysis.confidence, 1)}%` : analysis.confidence;
    const staleBanner = !inherited && (state.stale || event.ai_analysis_status === 'stale')
      ? '<div class="security-ai-stale">Análise potencialmente desatualizada após nova recorrência/evidência.</div>' : '';
    const inheritedHeader = inherited
      ? `<div class="mt-1"><span class="threat-intel-chip">Análise da campanha</span></div>
         <p class="subtle">Esta análise foi herdada da campanha correlacionada.</p>` : '';
    const actions = inherited
      ? `<button type="button" class="btn btn-sm btn-outline-primary mt-2" data-campaign-action="open" data-campaign-id="${esc(state.campaign_id || event.campaign_id || '')}">Abrir campanha</button>
         <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-security-action="reanalyze" data-event-id="${event.id}" ${canAnalyze ? '' : 'disabled'}>Analisar este evento individualmente</button>`
      : `<button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-security-action="reanalyze" data-event-id="${event.id}" ${canAnalyze ? '' : 'disabled'}>REANALISAR</button>`;
    return `${staleBanner}${inheritedHeader}
      <div class="security-ai-verdict"><strong>${esc(analysis.assessment || analysis.verdict || 'Análise consultiva')}</strong><span>${esc(confidence || '-')}</span></div>
      <p>${esc(analysis.summary || '')}</p>
      <h4>Por que foi detectado</h4>${investigationList(analysis.why_detected || analysis.evidence_for_attack)}
      <h4>Origens importantes</h4>${investigationList(analysis.important_sources)}
      <h4>Threat Intelligence</h4>${investigationList(analysis.threat_intelligence_findings || (analysis.threat_intel_interpretation ? [analysis.threat_intel_interpretation] : []))}
      <h4>Possíveis falsos positivos</h4>${investigationList(analysis.possible_false_positive_factors || analysis.evidence_against_attack)}
      <h4>Verificações recomendadas</h4>${investigationList(analysis.recommended_checks)}
      <h4>Ações recomendadas</h4>${investigationList(analysis.recommended_actions || (analysis.recommended_action ? [analysis.recommended_action] : []))}
      ${detailGrid([
        ['Mitigação (advisory only)', analysis.mitigation_advisory || (analysis.mitigation_recommended ? 'Requer validação humana e Policy Engine; nada foi executado.' : 'Nenhuma mitigação automática foi executada.')],
        ['Limitações', (analysis.limitations || []).join('; ')],
        ['Provider / modelo', `${state.provider || event.ai_provider || '-'} / ${state.model || event.ai_model || '-'}`],
        ['Gerada em', dateTime(state.analyzed_at || event.analyzed_at)],
        ['Versão', state.analysis_version || event.analysis_version || '-']
      ])}
      ${actions}
      <div class="subtle mt-1">Advisory only: a IA não executa nem solicita mitigação automática.</div>`;
  }

  function renderPersistedThreatIntel(event) {
    const source = event.threat_intel?.source_intel || {};
    const rows = Object.entries(source.sources || {}).flatMap(([ip, matches]) =>
      (Array.isArray(matches) ? matches : []).slice(0, 10).map(match => {
        const metadata = match.metadata && typeof match.metadata === 'object' ? JSON.stringify(match.metadata).slice(0, 500) : '-';
        return `<tr><td><code>${esc(ip)}</code></td><td>${esc(match.provider || '-')}</td><td>${esc(match.classification || match.indicator_type || '-')}</td>
          <td>${dateTime(match.last_seen)}</td><td>${esc(match.organization || '-')}</td><td>${esc(match.country || match.country_code || '-')}</td>
          <td>${esc(match.actor || '-')}</td><td>${esc((match.tags || []).join(', ') || '-')}</td><td>${esc((match.cves || []).join(', ') || '-')}</td><td title="${esc(metadata)}">${esc(metadata)}</td></tr>`;
      })
    ).slice(0, 50);
    return `<p><strong>${number(source.matched_source_count || source.matches)} de ${number(source.lookup_count)} origens consultadas</strong>${source.lookup_truncated ? ' (amostra limitada)' : ''}.</p>
      <p class="subtle">Enrichment persistido no evento; abrir o drawer não faz lookup individual. Reputação histórica não é apresentada como causa da detecção local.</p>
      ${rows.length ? `<div class="table-wrap"><table class="table table-sm security-wide-table"><thead><tr><th>IP</th><th>Provider</th><th>Classificação</th><th>Last seen</th><th>Organização</th><th>País</th><th>Actor</th><th>Tags</th><th>CVEs</th><th>Metadata</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>` : '<div class="subtle">Evento sem enrichment externo associado.</div>'}`;
  }

  function renderSecurityDistribution(items, label) {
    const rows = (Array.isArray(items) ? items : []).slice(0, 20);
    return rows.length ? `<div class="security-distribution"><h4>${esc(label)}</h4>${rows.map(item => `<div><strong>${esc(item.port ?? item.protocol_label ?? item.protocol ?? item.flags ?? '-')}</strong><span>${number(item.packets)} pacotes · ${securityBytes(item.bytes)} · ${number(item.flows)} flows</span></div>`).join('')}</div>` : '';
  }

  function sourceTableRows(items, sort) {
    return (items || []).slice().sort((left, right) => Number(right[sort] || 0) - Number(left[sort] || 0)).map(source =>
      `<tr><td><code>${esc(source.source_ip || '-')}</code></td><td>${source.source_asn ? `AS${number(source.source_asn)}` : '-'}<br><span class="subtle">${esc(source.asn_organization || '-')}</span></td>
        <td>${esc(source.country || '-')}</td><td>${number(source.packets)}</td><td>${securityBytes(source.bytes)}</td><td>${number(source.flows)}</td><td>${number(source.pps, 2)}</td><td>${number(source.share, 2)}%</td>
        <td>${esc(source.threat_intelligence_classification || '-')}<br><span class="subtle">${esc((source.threat_intelligence_providers || []).join(', ') || source.threat_intelligence_provider || '-')}</span></td></tr>`
    ).join('') || '<tr><td colspan="9" class="subtle">Sem origens agregadas disponíveis.</td></tr>';
  }

  function renderSecuritySources(items, distributed, sort = 'packets') {
    currentSecuritySources = Array.isArray(items) ? items.slice() : [];
    return `<div class="security-section-heading"><h3>${distributed ? 'Top Sources' : 'Origens'}</h3><div class="security-sort-controls" aria-label="Ordenar origens">
      ${['packets', 'bytes', 'pps'].map(value => `<button type="button" class="btn btn-sm ${sort === value ? 'btn-secondary' : 'btn-outline-secondary'}" data-security-source-sort="${value}">${value}</button>`).join('')}</div></div>
      <div class="table-wrap"><table class="table table-sm security-wide-table"><thead><tr><th>Source IP</th><th>ASN / organização</th><th>País</th><th>Pacotes</th><th>Bytes</th><th>Flows</th><th>pps</th><th>Share</th><th>Threat Intelligence</th></tr></thead><tbody id="securityEventSourceRows">${sourceTableRows(currentSecuritySources, sort)}</tbody></table></div>`;
  }

  function renderSecurityTimeline(traffic) {
    if (!(traffic?.items || []).length) return '<div class="subtle">Sem série temporal disponível.</div>';
    return `<div id="securityEventTrafficChart" class="security-event-traffic-chart" role="img" aria-label="Timeline de pps, bps, flows e origens"></div>
      <div class="subtle">Janela ${dateTime(traffic.query_window?.start)} – ${dateTime(traffic.query_window?.end)} · bucket ${number(traffic.query_window?.bucket_seconds)} s${traffic.query_window?.truncated ? ' · limitada por segurança' : ''}${traffic.available ? '' : ' · resumo persistido'}</div>`;
  }

  function mountSecurityTimeline(traffic) {
    const element = document.getElementById('securityEventTrafficChart');
    if (!element || !root.echarts) return;
    securityTrafficChart?.dispose();
    securityTrafficChart = root.echarts.init(element);
    const items = traffic.items || [];
    securityTrafficChart.setOption({
      animation: false, tooltip: { trigger: 'axis' },
      legend: { data: ['pps', 'bps', 'flows/s', 'origens'], textStyle: { color: '#94a3b8' } },
      grid: { left: 58, right: 58, top: 42, bottom: 42 },
      xAxis: { type: 'category', data: items.map(item => item.timestamp), axisLabel: { formatter: value => dateTime(value).split(' ')[1] || value } },
      yAxis: [{ type: 'value', name: 'pps / flows' }, { type: 'value', name: 'bps' }],
      series: [
        { name: 'pps', type: 'line', showSymbol: false, data: items.map(item => item.pps), markArea: { silent: true, itemStyle: { color: 'rgba(239,68,68,.14)' }, data: [[{ xAxis: traffic.event_interval?.start }, { xAxis: traffic.event_interval?.end }]] } },
        { name: 'bps', type: 'line', yAxisIndex: 1, showSymbol: false, data: items.map(item => item.bps) },
        { name: 'flows/s', type: 'line', showSymbol: false, data: items.map(item => item.flows) },
        { name: 'origens', type: 'line', showSymbol: false, data: items.map(item => item.source_count) }
      ]
    });
  }

  function isScanFamily(event) {
    const family = String(event.attack_family || '').toUpperCase();
    const type = String(event.attack_type || '').toUpperCase();
    return family === 'SCAN_FAMILY' || ['PORT_SCAN_HORIZONTAL', 'PORT_SCAN_VERTICAL', 'NETWORK_SWEEP', 'LOW_SLOW_SCAN'].includes(type);
  }

  function eventSpanDays(event) {
    const first = new Date(event.first_seen).getTime();
    const last = new Date(event.last_seen).getTime();
    if (!Number.isFinite(first) || !Number.isFinite(last) || last < first) return 0;
    return Math.round((last - first) / 86400000);
  }

  function renderRecurrenceBadge(event) {
    const count = Number(event.recurrence_count || 0);
    if (count <= 1) return '';
    const days = eventSpanDays(event);
    return `<div class="security-recurrence-badge" role="note">
      <span class="threat-intel-chip threat-intel-chip--hot">RECORRENTE</span>
      <span>${number(count)} ocorrência${count === 1 ? '' : 's'}${days > 1 ? ` · observado em ~${days} dia${days === 1 ? '' : 's'}` : ''}</span>
    </div>`;
  }

  function renderSnapshotVsAccumulated(event) {
    const detection = event.investigation?.detection_evidence || {};
    const observed = detection.observed || {};
    const facts = event.evidence?.facts || [];
    const duration = event.duration_seconds ?? 0;
    const days = eventSpanDays(event);
    return `<div class="security-scope-grid">
      <div class="security-scope-card">
        <h4>Janela que confirmou a detecção</h4>
        ${detailGrid([
          ['Destinos na janela', detection.destination_diversity ?? '-'],
          ['Pacotes na janela', observed.packets ?? '-'],
          ['Amostras', detection.samples ?? '-'],
          ['Duração da janela', detection.window_seconds ? `${number(detection.window_seconds)} s` : '-']
        ])}
        ${facts.length ? `<div class="subtle">${facts.map(fact => esc(fact)).join(' · ')}</div>` : ''}
      </div>
      <div class="security-scope-card">
        <h4>Evento acumulado</h4>
        ${detailGrid([
          ['Destinos únicos', event.unique_destinations ?? '-'],
          ['Portas de destino', event.unique_dst_ports ?? '-'],
          ['Pacotes / flows', `${number(event.packets)} / ${number(event.flows)}`],
          ['Recorrências', event.recurrence_count ?? 1],
          ['Primeira ocorrência', dateTime(event.first_seen)],
          ['Última ocorrência', dateTime(event.last_seen)],
          ['Duração total', days > 1 ? `${days} dia${days === 1 ? '' : 's'}` : `${number(duration, 0)} s`]
        ])}
      </div>
    </div>`;
  }

  function renderDetectionScoreBlock(event) {
    return `<div class="security-score-block">
      <h4>Detecção</h4>
      <div><strong>Detector score: ${number(event.detector_score)}/100</strong> <span class="subtle">· confiança ${number(event.confidence, 1)}%</span></div>
      <div class="subtle">Mede a força da evidência da assinatura ${esc(event.attack_type || 'detectada')}.</div>
    </div>`;
  }

  function scoreComponentLabel(key) {
    return ({
      cardinality: 'Cardinalidade', persistence: 'Persistência', syn_attempts: 'SYN sem ACK',
      threat_intel: 'Threat Intel', baseline_deviation: 'Desvio do baseline', rate: 'Taxa', volume: 'Volume'
    })[String(key)] || String(key);
  }

  function primaryEvidenceForEvent(event) {
    const detection = event.investigation?.detection_evidence || {};
    const facts = event.evidence?.facts || [];
    if (isScanFamily(event)) {
      const rows = [];
      if (detection.destination_diversity !== undefined) {
        const threshold = detection.configured_thresholds?.unique_destination_hosts;
        rows.push(['Cardinalidade de destinos', `${number(detection.destination_diversity)} observados${threshold ? ` ≥ ${number(threshold)} threshold` : ''}`]);
      }
      const synFact = facts.find(fact => /SYN/i.test(fact));
      if (synFact) rows.push(['SYN sem ACK', synFact]);
      const persistenceFact = facts.find(fact => /persistência/i.test(fact));
      if (persistenceFact) rows.push(['Persistência', persistenceFact]);
      const recFact = facts.find(fact => /recorrência/i.test(fact));
      if (!recFact && Number(event.recurrence_count || 0) > 1) rows.push(['Recorrência', `${number(event.recurrence_count)} ocorrências`]);
      if (!rows.length) rows.push(['Cardinalidade', detection.destination_diversity ?? event.unique_destinations ?? '-']);
      return rows;
    }
    const rows = [];
    if (event.packets_per_second) rows.push(['pps', number(event.packets_per_second, 2)]);
    if (event.bits_per_second) rows.push(['bps', number(event.bits_per_second, 1)]);
    if (Number(event.baseline_deviation)) rows.push(['Desvio do baseline', `${number(event.baseline_deviation, 2)}x`]);
    if (Number(event.unique_sources) > 1) rows.push(['Origens', number(event.unique_sources)]);
    rows.push(['Protocolo / portas', `${event.protocol || '-'} / ${number(event.unique_dst_ports)}`]);
    return rows;
  }

  function renderExternalReputation(event) {
    const source = event.threat_intel?.source_intel || {};
    const matched = Number(source.matched_source_count || source.matches || 0);
    const looked = Number(source.lookup_count || 0);
    return `<div class="security-reputation">
      <h4>Reputação externa</h4>
      ${matched > 0
        ? `<p>${number(matched)} de ${number(looked)} origens consultadas possuem histórico em Threat Intelligence.</p>`
        : '<p class="subtle">Sem dados disponíveis.</p>'}
      <h4>Detecção local</h4>
      <div><span class="threat-source-badge source-gmj">GMJ-FLOW</span> <strong>${esc(event.verdict || 'INFO')}</strong></div>
      <p class="subtle">Ausência de reputação externa não invalida a evidência comportamental local.</p>
    </div>`;
  }

  function renderSecurityTarget(event) {
    const network = event.network_context || {};
    const target = event.target_prefix || event.target_ip;
    const distributed = isScanFamily(event) && Number(event.unique_destinations || 0) > 1;
    if (!target && distributed) {
      return detailGrid([
        ['Alvo agregado', `Múltiplos clientes/destinos (${number(event.unique_destinations)} únicos)`],
        ['Origem agregada', event.src_ip || 'distribuída'],
        ['Role / contexto', event.dst_role || network.dst_role || 'CUSTOMER'],
        ['Interface', `in ${event.input_if || '-'} / out ${event.output_if || '-'}`],
        ['Sensor / exporter', `${event.sensor || '-'} / ${event.exporter || '-'}`],
        ['CGNAT', event.cgnat_context || 'não identificado']
      ]);
    }
    return detailGrid([
      ['IP / prefixo', target || '-'],
      ['Role / contexto', event.dst_role || network.dst_role || '-'],
      ['ASN', network.dst_asn || network.target_asn || '-'],
      ['ASN name', network.dst_as_name || network.target_as_name || '-'],
      ['Interface', `in ${event.input_if || '-'} / out ${event.output_if || '-'}`],
      ['Customer / network', network.customer_name || network.zone_name || network.network_name || network.description || '-'],
      ['Sensor / exporter', `${event.sensor || '-'} / ${event.exporter || '-'}`],
      ['CGNAT', event.cgnat_context || 'não identificado']
    ]);
  }

  function renderDetectionEvidence(event) {
    const detection = event.investigation?.detection_evidence || {};
    const observed = detection.observed || {};
    const thresholds = detection.configured_thresholds || {};
    const thresholdEntries = Object.entries(thresholds);
    const observedByKey = {
      unique_destination_hosts: detection.destination_diversity,
      unique_destinations: detection.destination_diversity,
      unique_sources: detection.source_count
    };
    const resultText = thresholdEntries.length
      ? thresholdEntries.map(([key, value]) => {
          const actual = observedByKey[key] ?? observed[key];
          return actual === undefined || actual === null
            ? `${key}: threshold ${number(value)}`
            : `${key}: observado ${number(actual)} ${Number(actual) >= Number(value) ? '≥' : '<'} threshold ${number(value)}`;
        }).join(' · ')
      : (event.detection_reason || '-');

    // Baseline volumétrico é relevante apenas quando é o sinal dominante.
    // Para SCAN_FAMILY o sinal é cardinalidade/SYN/persistência, não volume.
    const scan = isScanFamily(event);
    const baselineRows = [
      ['Baseline', detection.baseline],
      ['Observed', detection.observed_value],
      ['Delta', detection.delta],
      ['MAD', detection.mad],
      ['Robust z-score', detection.robust_z_score],
      ['Confidence', detection.confidence],
      ['Maturity', detection.maturity],
      ['Bucket', detection.bucket],
      ['Classification', detection.classification]
    ].filter(([, value]) => value !== null && value !== undefined && value !== '');
    const hasBaseline = baselineRows.length > 0;

    const scoreComponents = Object.entries(event.score_components || {}).map(([key, value]) => [scoreComponentLabel(key), value]);

    return `<h4>Sinal principal da detecção</h4>${detailGrid(primaryEvidenceForEvent(event))}
      <h4>Limiar que disparou</h4>${detailGrid([
        ['Threshold configurado', thresholdEntries.map(([key, value]) => `${key}=${value}`).join(' · ') || 'Não persistido'],
        ['Resultado', resultText],
        ['Janela / amostras', `${number(detection.window_seconds)} s / ${number(detection.samples)}`],
        ['Origens / ASNs / destinos (janela)', `${number(detection.source_count ?? '-')} / ${number(detection.asn_diversity ?? '-')} / ${number(detection.destination_diversity ?? '-')}`],
        ['Detector (engine)', event.detector || '-'],
        ['Regra responsável', `${event.attack_family || '-'} / ${event.attack_type || '-'}`]
      ])}
      ${hasBaseline
        ? `<h4>Baseline volumétrico</h4>${scan && !Number(detection.baseline) ? '<div class="subtle">Não aplicável como sinal principal para esta família; exibido apenas como contexto.</div>' : ''}${detailGrid(baselineRows)}`
        : (scan ? '<h4>Baseline volumétrico</h4><div class="subtle">Sem baseline volumétrico relevante para esta família.</div>' : '')}
      <h4>Fatos usados pelo detector</h4>${investigationList(event.evidence?.facts)}
      <h4>Composição do Detector Score</h4>${detailGrid(scoreComponents)}`;
  }

  function renderSecurityEventInvestigation(event, related, traffic, sources, aiState) {
    currentSecurityEvent = event;
    const network = event.network_context || {};
    const investigation = event.investigation || {};
    const duration = event.duration_seconds ?? Math.max(0, (new Date(event.last_seen) - new Date(event.first_seen)) / 1000);
    const canManage = canManageSecurityEvents();
    setInvestigationHeading('Security Event Investigation', `${event.attack_type} · ${event.event_id || `#${event.id}`}`);
    document.getElementById('securityEventDrawerBody').innerHTML = `
      <nav class="security-event-section-nav" aria-label="Seções da investigação">${[['summary','Resumo'],['traffic','Tráfego'],['sources','Origens'],['ports','Portas'],['intel','Threat Intelligence'],['evidence','Evidências'],['ai','Análise IA']].map(([id, label]) => `<a href="#security-event-${id}">${label}</a>`).join('')}</nav>
      <section id="security-event-summary">
        ${renderRecurrenceBadge(event)}
        <h3>Resumo</h3>${detailGrid([
          ['Event ID', event.event_id || event.id], ['Event type', event.attack_type], ['Família', event.attack_family], ['Severity', event.severity],
          ['Status / verdict', `${event.status} / ${event.verdict}`],
          ['Origem → alvo', `${event.src_ip || 'distribuída'} → ${event.target_prefix || event.target_ip || (Number(event.unique_destinations) > 1 ? `${number(event.unique_destinations)} destinos acumulados` : '-')}`],
          ['Detector', event.detector]
        ])}
        <div class="security-score-stack">
          ${renderDetectionScoreBlock(event)}
          ${renderThreatScore(event)}
        </div>
        ${renderSnapshotVsAccumulated(event)}
        ${renderSecurityEventLineage(event)}
        <h4>Alvo</h4>${renderSecurityTarget(event)}
      </section>
      <section id="security-event-traffic"><h3>Tráfego observado (evento acumulado)</h3>${detailGrid([
        ['Protocolo', event.protocol], ['Origens / destinos', `${number(event.unique_sources)} / ${number(event.unique_destinations)}`],
        ['Pacotes / bytes', `${number(event.packets)} / ${securityBytes(event.bytes)}`], ['pps / bit/s', `${number(event.packets_per_second, 2)} / ${number(event.bits_per_second, 1)}`],
        ['Flows / flows/s', `${number(event.flows)} / ${number(event.flows_per_second, 2)}`], ['Portas src / dst', `${number(event.unique_src_ports)} / ${number(event.unique_dst_ports)}`]
      ])}<h4>Timeline (janela limitada por segurança, não representa toda a duração acumulada)</h4>${renderSecurityTimeline(traffic)}</section>
      <section id="security-event-sources">${renderSecuritySources(sources.items || investigation.top_sources || [], Boolean(sources.distributed || event.unique_sources > 1))}</section>
      <section id="security-event-ports"><h3>Portas e protocolos</h3>${renderSecurityDistribution(investigation.top_destination_ports, 'Top Destination Ports')}${renderSecurityDistribution(investigation.top_source_ports, 'Top Source Ports')}${renderSecurityDistribution(investigation.protocols, 'Distribuição por protocolo')}${renderSecurityDistribution(investigation.tcp_flags, 'TCP Flags (SYN / ACK / RST)')}
        ${!(investigation.top_destination_ports || []).length && !(investigation.top_source_ports || []).length ? '<div class="subtle">Evento legado sem distribuição persistida. Use “Ver evidências” para consultar agregados limitados.</div>' : ''}</section>
      <section id="security-event-intel"><h3>Threat Intelligence</h3>${renderExternalReputation(event)}${renderPersistedThreatIntel(event)}</section>
      <section id="security-event-evidence"><div class="security-section-heading"><h3>Evidências</h3><button type="button" class="btn btn-sm btn-outline-secondary" data-security-action="evidence" data-event-id="${event.id}">VER EVIDÊNCIAS</button></div>${renderDetectionEvidence(event)}<div id="securityEventEvidenceSamples"></div></section>
      <section id="security-event-ai"><h3>Análise IA</h3>${renderSecurityAiInvestigation(event, aiState)}</section>
      <section><h3>Eventos relacionados</h3>${related.length ? investigationList(related.map(item => `${item.event_id || `#${item.id}`} ${item.attack_type} · ${item.verdict} · ${dateTime(item.last_seen)}`)) : '<div class="subtle">Nenhum evento relacionado.</div>'}</section>
      <footer class="security-event-review-actions">
        <button type="button" class="btn btn-sm btn-outline-primary" data-security-action="open-in-threat-intel" data-event-id="${event.id}">ABRIR NO THREAT INTELLIGENCE</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-security-action="status" data-status="investigating" data-event-id="${event.id}" ${canManage ? '' : 'disabled'}>Investigando</button>
        <button type="button" class="btn btn-sm btn-outline-success" data-security-action="status" data-status="benign" data-event-id="${event.id}" ${canManage ? '' : 'disabled'}>Marcar benigno</button>
        <button type="button" class="btn btn-sm btn-outline-danger" data-security-action="status" data-status="confirmed" data-event-id="${event.id}" ${canManage ? '' : 'disabled'}>Confirmar ataque</button>
      </footer>`;
    requestAnimationFrame(() => mountSecurityTimeline(traffic));
    root.lucide?.createIcons();
  }

  function renderAggregatedEvidence(payload) {
    const element = document.getElementById('securityEventEvidenceSamples');
    if (!element) return;
    const conversations = payload.sample_conversations || [];
    element.innerHTML = `<h4>Amostra agregada de conversas (${number(conversations.length)} / limite ${number(payload.limits?.sample_conversations)})</h4>
      <p class="subtle">Nenhum flow_raw é retornado; os dados vêm de agregações temporais limitadas.</p>
      ${conversations.length ? `<div class="table-wrap"><table class="table table-sm security-wide-table"><thead><tr><th>Origem</th><th>Destino</th><th>Portas</th><th>Protocolo</th><th>Flags</th><th>Pacotes</th><th>Bytes</th><th>Flows</th></tr></thead><tbody>${conversations.map(item => `<tr><td><code>${esc(item.source_ip)}</code></td><td><code>${esc(item.destination_ip)}</code></td><td>${number(item.src_port)} → ${number(item.dst_port)}</td><td>${esc(item.protocol)}</td><td>${number(item.tcp_flags)}</td><td>${number(item.packets)}</td><td>${securityBytes(item.bytes)}</td><td>${number(item.flows)}</td></tr>`).join('')}</tbody></table></div>` : '<div class="subtle">Sem conversas agregadas disponíveis.</div>'}
      ${renderSecurityDistribution(payload.top_destination_ports, 'Top Destination Ports (agregado)')}${renderSecurityDistribution(payload.top_source_ports, 'Top Source Ports (agregado)')}${renderSecurityDistribution(payload.protocols, 'Protocolos (agregado)')}`;
  }

  function renderInvestigationUnavailable(eventId, error) {
    setInvestigationHeading('Security Event Investigation', `Detecção informativa · #${esc(eventId)}`);
    document.getElementById('securityEventDrawerBody').innerHTML = `
      <section><h3>Evidências da detecção</h3>
        <p>Esta é uma detecção comportamental informativa e ainda não possui Anomaly/Security Event correlacionado acessível.</p>
        ${error ? `<p class="subtle">Detalhe técnico: ${esc(error.message || error)}</p>` : ''}
      </section>`;
    root.lucide?.createIcons();
  }

  function renderSecurityEventLineage(event) {
    return `<div class="security-event-lineage"><h4>Rastreabilidade</h4>${detailGrid([
      ['Observation / Security Event', event.event_id || `#${event.id}`],
      ['Detector (engine)', event.detector || '-'],
      ['Regra responsável', `${event.attack_family || '-'} / ${event.attack_type || '-'}`],
      ['Anomaly', event.anomaly_id ? `#${number(event.anomaly_id)}` : 'Sem anomalia associada'],
      ['Campanha', event.campaign_id ? esc(event.campaign_id) : 'Não correlacionada']
    ])}</div>`;
  }

  async function openSecurityEventInvestigation(eventId) {
    currentSecurityCampaignId = null;
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('security-event-drawer-open');
    document.getElementById('securityEventDrawerStatus').textContent = 'Carregando investigação...';
    const base = `/api/security/events/${encodeURIComponent(eventId)}`;
    let event;
    try {
      event = await apiRequest(base);
    } catch (error) {
      document.getElementById('securityEventDrawerStatus').textContent = '';
      renderInvestigationUnavailable(eventId, error);
      return;
    }
    currentSecurityEventId = Number(event.id);
    // Renderiza o nucleo da investigacao imediatamente com o payload do evento
    // (garante que o drawer NUNCA fique vazio) e depois enriquece cada secao de
    // forma independente: uma falha parcial nao apaga a investigacao inteira.
    renderSecurityEventInvestigation(event, [], { items: [] }, { items: [] }, {});
    document.getElementById('securityEventDrawerStatus').textContent = 'Enriquecendo investigação...';
    const results = await Promise.allSettled([
      apiRequest(`${base}/related?limit=20`),
      apiRequest(`${base}/traffic?padding_seconds=600`),
      apiRequest(`${base}/sources?sort=packets&limit=100`),
      apiRequest(`${base}/ai-analysis`)
    ]);
    const value = result => (result.status === 'fulfilled' ? result.value : {});
    renderSecurityEventInvestigation(
      event,
      value(results[0]).items || [],
      value(results[1]),
      value(results[2]),
      value(results[3])
    );
    document.getElementById('securityEventDrawerStatus').textContent = '';
  }

  function campaignPersistence(campaign) {
    if (campaign.persistence === 'satisfied' || campaign.persistence_satisfied === true) return 'satisfeita';
    if (campaign.persistence === 'insufficient' || campaign.persistence_satisfied === false) return 'insuficiente';
    return 'não registrada';
  }

  function campaignRiskLabel(band) {
    return ({ informational: 'Informativo', suspicious: 'Suspeito', needs_review: 'Revisão', elevated: 'Elevado', critical: 'Crítico' })[band] || band || '-';
  }

  function renderCampaignRiskBadge(campaign) {
    const score = Number(campaign.campaign_risk_score ?? 0);
    const band = campaign.campaign_risk_band || '';
    return `<div class="mt-1"><span class="threat-score ${scoreClass(score)}">${number(score)}</span> <span class="subtle">${esc(campaignRiskLabel(band))} · priorização</span></div>`;
  }

  function renderCampaignRiskScore(campaign) {
    const components = campaign.campaign_risk_components || {};
    const score = Number(campaign.campaign_risk_score ?? 0);
    const band = campaign.campaign_risk_band || '';
    const rows = [
      ['Coordenação', components.coordination],
      ['Desvio de tráfego', components.traffic_deviation],
      ['Recorrência', components.recurrence],
      ['Threat Intelligence', components.threat_intel],
      ['Eventos correlacionados', components.security_events],
      ['Persistência', components.persistence]
    ];
    return `<div class="campaign-risk-score">
      <div class="security-ai-verdict"><strong>${number(score)} / 100</strong><span>${esc(campaignRiskLabel(band))}</span></div>
      <div class="table-wrap"><table class="table table-sm security-wide-table"><thead><tr><th>Componente</th><th>Pontos</th></tr></thead><tbody>${rows.map(([label, pts]) => `<tr><td>${label}</td><td>${number(pts)}</td></tr>`).join('')}</tbody></table></div>
      <p class="subtle">Score de priorização — não executa bloqueio e não alimenta decisão automática de mitigação.</p>
    </div>`;
  }

  function campaignEnrichmentText(campaign) {
    const summary = campaign.enrichment_summary || {};
    if (!summary.available) return 'Sem enrichment persistido';
    const parts = [
      `${optionalNumber(summary.matched_sources)} fontes com match`,
      summary.target_matches ? `${number(summary.target_matches)} correlações de alvo` : '',
      (summary.providers || []).join(', '),
      (summary.classifications || []).join(', ')
    ].filter(Boolean);
    return parts.join(' · ') || 'Enrichment persistido';
  }

  function renderCampaignThreatIntel(campaign) {
    const threat = campaign.threat_intel || {};
    const source = threat.source_intel || {};
    const target = threat.target_campaign_intel || {};
    const sourceRows = Object.entries(source.sources || {}).flatMap(([ip, matches]) =>
      (Array.isArray(matches) ? matches : []).slice(0, 10).map(match => `<tr><td><code>${esc(ip)}</code></td><td>${esc(match.provider || '-')}</td>
        <td>${esc(match.classification || match.indicator_type || '-')}</td><td>${esc(match.organization || '-')}</td><td>${esc((match.tags || []).join(', ') || '-')}</td><td>${dateTime(match.last_seen)}</td></tr>`)
    ).slice(0, 50);
    const summary = campaign.enrichment_summary || {};
    if (!summary.available) {
      return '<div class="subtle">Campanha sem enrichment externo associado.</div><p class="subtle">Abrir o drawer não executa lookup individual.</p>';
    }
    return `<p><strong>${esc(campaignEnrichmentText(campaign))}</strong></p>
      <p class="subtle">Enrichment persistido na campaign; abrir o drawer não faz lookup individual. Threat Intelligence permanece separada da evidência do detector.</p>
      ${sourceRows.length ? `<div class="table-wrap"><table class="table table-sm security-wide-table"><thead><tr><th>Source IP</th><th>Provider</th><th>Classificação</th><th>Organização</th><th>Tags</th><th>Last seen</th></tr></thead><tbody>${sourceRows.join('')}</tbody></table></div>` : ''}
      ${(target.observations || []).length ? `<h4>Correlação de alvo persistida</h4>${investigationList(target.observations.map(item => `${item.provider || 'External'} · ${item.method || item.protocol || 'observação'}`))}` : ''}`;
  }

  function renderCampaignAsnDistribution(items) {
    const rows = Array.isArray(items) ? items : [];
    return rows.length ? `<div class="table-wrap"><table class="table table-sm security-wide-table"><thead><tr><th>ASN</th><th>Organização</th><th>País</th><th>Fontes</th><th>Percentual</th></tr></thead><tbody>${rows.map(item => `<tr>
      <td>${item.asn ? `AS${number(item.asn)}` : '-'}</td><td>${esc(item.organization || '-')}</td><td>${esc(item.country || '-')}</td><td>${optionalNumber(item.sources)}</td><td>${optionalNumber(item.percentage, 2, '%')}</td>
    </tr>`).join('')}</tbody></table></div>` : '<div class="subtle">Distribuição por ASN não persistida para esta campanha.</div>';
  }

  function renderCampaignEvents(items) {
    const events = Array.isArray(items) ? items : [];
    if (!events.length) return '<div class="subtle">Nenhum Security Event canônico correlacionado a esta campanha.</div>';
    return events.map(item => {
      const intel = item.threat_intelligence || {};
      const intelText = intel.matched_sources || (intel.providers || []).length
        ? `${number(intel.matched_sources)} fontes · ${(intel.providers || []).join(', ') || 'enrichment persistido'}`
        : 'sem enrichment persistido';
      return `<article class="security-correlated-event">
        ${detailGrid([
          ['Public ID', item.public_id], ['Event type', item.event_type], ['Score', optionalNumber(item.score)], ['Target', item.target],
          ['First seen', dateTime(item.first_seen)], ['Last seen', dateTime(item.last_seen)], ['Source count', optionalNumber(item.source_count)], ['Threat Intelligence', intelText],
          ['Source ASN', item.source_asn ? `AS${number(item.source_asn)} — ${item.source_asn_organization || '-'} · ${item.source_country || '-'}` : '-'],
          ['Target ASN', item.target_asn ? `AS${number(item.target_asn)} — ${item.target_asn_organization || '-'} · ${item.target_country || '-'}` : '-']
        ])}
        <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-security-action="open" data-event-id="${esc(item.id)}">Abrir evento</button>
      </article>`;
    }).join('');
  }

  function renderCampaignAiInvestigation(campaign, state = {}) {
    const analysis = state.analysis && Object.keys(state.analysis).length ? state.analysis : {};
    const hasAnalysis = Object.keys(analysis).length > 0;
    const canAnalyze = canManageSecurityEvents() && state.enabled === true && state.configured === true;
    const unavailable = !state.enabled
      ? 'Security AI desabilitada por configuração.'
      : !state.configured
        ? 'Provider, modelo ou credencial não configurados no backend.'
        : !canManageSecurityEvents() ? 'Seu perfil não pode solicitar análise.' : '';
    const status = detailGrid([
      ['IA habilitada', state.enabled ? 'Sim' : 'Não'], ['Rota configurada', state.route_configured ? 'Sim' : 'Não — fallback por ambiente'],
      ['Rota habilitada', state.route_configured ? (state.route_enabled ? 'Sim' : 'Não') : '-'],
      ['Provider', state.provider_name || state.provider || '-'], ['Modelo', state.model || '-'],
      ['Status da análise', state.analysis_status || 'not_analyzed'], ['Analisada em', dateTime(state.analyzed_at)],
      ['Cache / desatualização', state.stale ? 'desatualizada' : hasAnalysis ? 'válido / reutilizável' : 'sem cache']
    ]);
    if (!hasAnalysis) {
      return `${status}<p class="subtle mt-2">Esta campanha ainda não foi analisada por IA. A execução ocorre somente mediante clique e é consultiva.</p>
        ${state.error ? `<div class="security-ai-error">${esc(state.error)}</div>` : ''}
        <button type="button" class="btn btn-sm btn-success mt-2" data-campaign-action="analyze" data-campaign-id="${esc(campaign.campaign_id)}" ${canAnalyze ? '' : 'disabled'}>ANALISAR COM IA</button>
        ${unavailable ? `<div class="subtle mt-1">${esc(unavailable)}</div>` : ''}`;
    }
    return `${status}${state.error ? `<div class="security-ai-error mt-2">Última tentativa: ${esc(state.error)}</div>` : ''}${state.stale ? '<div class="security-ai-stale mt-2">Análise potencialmente desatualizada após nova evidência da campanha.</div>' : ''}
      <div class="security-ai-verdict"><strong>${esc(analysis.assessment || 'Análise consultiva')}</strong><span>${esc(analysis.confidence || '-')}</span></div>
      <p>${esc(analysis.summary || '')}</p>
      <h4>Por que a campanha foi detectada</h4>${investigationList(analysis.why_detected)}
      <h4>Origens importantes</h4>${investigationList(analysis.important_sources)}
      <h4>Threat Intelligence</h4>${investigationList(analysis.threat_intelligence_findings)}
      <h4>Possíveis falsos positivos</h4>${investigationList(analysis.possible_false_positive_factors)}
      <h4>Verificações recomendadas</h4>${investigationList(analysis.recommended_checks)}
      <h4>Ações recomendadas</h4>${investigationList(analysis.recommended_actions)}
      ${detailGrid([
        ['Mitigação (advisory only)', analysis.mitigation_advisory || 'Nenhuma mitigação automática foi executada.'],
        ['Limitações', (analysis.limitations || []).join('; ')], ['Provider / modelo', `${state.provider || '-'} / ${state.model || '-'}`],
        ['Gerada em', dateTime(state.analyzed_at)], ['Versão', state.analysis_version || '-']
      ])}
      <button type="button" class="btn btn-sm btn-outline-secondary mt-2" data-campaign-action="reanalyze" data-campaign-id="${esc(campaign.campaign_id)}" ${canAnalyze ? '' : 'disabled'}>REANALISAR</button>
      <div class="subtle mt-1">Advisory only: a IA não executa nem solicita mitigação automática.</div>`;
  }

  function renderCampaignDetectionContext(context = {}) {
    return `<div class="campaign-context-box"><p>${esc(context.interpretation || 'Contexto de detecção não persistido.')}</p>${detailGrid([
      ['Role do alvo', context.target_role], ['PPS observado', optionalNumber(context.observed_pps, 2)],
      ['Baseline', optionalNumber(context.baseline_pps, 2, ' pps')], ['Delta', optionalNumber(context.baseline_delta, 2, 'x')],
      ['Máximo por host', optionalNumber(context.max_per_host_pps, 2, ' pps')], ['Quantidade de fontes', optionalNumber(context.source_count)],
      ['Diversidade de ASN', optionalNumber(context.asn_diversity)], ['Destinos', optionalNumber(context.destination_count)],
      ['Threat Intelligence', context.threat_intelligence_status]
    ])}</div>`;
  }

  function renderCampaignContextEvaluation(evaluation = {}) {
    const metrics = evaluation.metrics || {};
    const signals = evaluation.signals || {};
    const context = evaluation.context || {};
    return `${detailGrid([
      ['Estado operacional', String(evaluation.state || '-').toUpperCase()],
      ['Confiança de ataque', localizedLevel(evaluation.attack_confidence)],
      ['Risco de falso positivo', localizedRisk(evaluation.false_positive_risk)],
      ['Role do alvo', context.target_role || context.network_role],
      ['Baseline PPS / BPS', `${optionalNumber(metrics.baseline_pps, 2)} / ${optionalNumber(metrics.baseline_bps, 1)}`],
      ['Delta / razão do baseline', `${optionalNumber(metrics.baseline_delta, 2)} / ${optionalNumber(metrics.baseline_ratio, 2)}`],
      ['Pico PPS / BPS', `${optionalNumber(metrics.peak_pps, 2)} / ${optionalNumber(metrics.peak_bps, 1)}`],
      ['Máximo por host PPS / BPS', `${optionalNumber(metrics.max_pps_per_host, 2)} / ${optionalNumber(metrics.max_bps_per_host, 1)}`],
      ['Fontes / ASNs', `${optionalNumber(metrics.source_count)} / ${optionalNumber(metrics.asn_count)}`],
      ['Attack Vectors correlacionados', optionalNumber(metrics.correlated_attack_vector_count)],
      ['Security Events correlacionados', optionalNumber(metrics.correlated_security_event_count)],
      ['Threat Intelligence relevante', signals.relevant_threat_intel ? 'Sim' : 'Não'],
      ['Análise por IA sugerida', evaluation.should_analyze_ai ? 'Sim' : 'Não']
    ])}<h4>Motivos determinísticos</h4>${investigationList(evaluation.reasons, 'Nenhum motivo determinístico registrado.')}
      <p class="subtle">Avaliação baseada somente em dados locais persistidos. O score comportamental não representa probabilidade de ataque e esta avaliação não aciona mitigação.</p>`;
  }

  function provenanceWindow(item = {}) {
    const interval = item.first_seen || item.last_seen ? `${dateTime(item.first_seen)} → ${dateTime(item.last_seen)}` : 'timestamp do pico não persistido';
    const windows = (item.contributing_window_seconds || []).length ? ` · janelas detector ${item.contributing_window_seconds.join(', ')} s` : '';
    return `${esc(item.scope || '-')} · ${esc(item.aggregation || '-')}${windows} · ${interval}`;
  }

  function renderSecurityCampaignInvestigation(payload, aiState) {
    const campaign = payload.campaign || {};
    const traffic = payload.target_traffic || {};
    const evidence = payload.detection_correlation_evidence || {};
    const provenance = payload.metric_provenance || {};
    const detectionContext = payload.detection_context || {};
    const contextEvaluation = payload.context_evaluation || campaign.context_evaluation || {};
    const asnContext = payload.asn_distribution_context || {};
    const ports = (traffic.ports || []).map(item => item.port).filter(value => value !== null && value !== undefined).join(', ');
    setInvestigationHeading('Investigação da campanha', `Investigação da campanha · ${campaign.campaign_id}`);
    document.getElementById('securityEventDrawerBody').innerHTML = `
      <nav class="security-event-section-nav" aria-label="Seções da investigação da campanha">${[['summary','Resumo'],['risk','Risk Score'],['context','Contexto'],['traffic','TARGET / TRAFFIC'],['sources','TOP SOURCES'],['asn','ASN SNAPSHOT'],['intel','Threat Intelligence'],['events','Eventos correlacionados'],['evidence','Evidências'],['ai','Análise IA']].map(([id, label]) => `<a href="#campaign-${id}">${label}</a>`).join('')}</nav>
      <section id="campaign-summary"><h3>RESUMO DA CAMPANHA</h3>${detailGrid([
        ['ID da campanha', campaign.campaign_id], ['Classificação / família', `${campaign.classification || '-'} / ${campaign.family || '-'}`],
        ['Alvo', campaign.target], ['Score comportamental', optionalNumber(campaign.coordination_score)],
        ['Fontes', optionalNumber(campaign.unique_sources)], ['Quantidade de ASNs', optionalNumber(campaign.unique_source_asns)],
        ['Pico PPS da detecção', optionalNumber(campaign.packets_per_second, 2)], ['Pico BPS da detecção', optionalNumber(campaign.bits_per_second, 1)],
        ['Primeira observação', dateTime(campaign.first_seen)], ['Última observação', dateTime(campaign.last_seen)],
        ['Duração da campanha', humanDuration(campaign.duration_seconds)],
        ['Duração técnica', campaign.duration_seconds === null || campaign.duration_seconds === undefined ? '-' : `${number(campaign.duration_seconds, 3)} s`],
        ['Persistência', campaignPersistence(campaign)], ['Detector', campaign.detector], ['Resumo do enrichment', campaignEnrichmentText(campaign)]
      ])}<p class="subtle score-semantics">O score comportamental reflete critérios locais de correlação; não representa probabilidade de ataque.</p></section>
      <section id="campaign-risk"><h3>CAMPAIGN RISK SCORE</h3>${renderCampaignRiskScore(campaign)}</section>
      <section id="campaign-context"><h3>AVALIAÇÃO CONTEXTUAL DETERMINÍSTICA</h3>${renderCampaignContextEvaluation(contextEvaluation)}<h4>Contexto de detecção / CGNAT</h4>${renderCampaignDetectionContext(detectionContext)}</section>
      <section id="campaign-traffic"><h3>TARGET / TRAFFIC</h3>${detailGrid([
        ['Target', traffic.target], ['Target role', traffic.target_role], ['Protocol', traffic.protocol], ['Ports', ports || '-'],
        ['Peak detection PPS', optionalNumber(traffic.pps, 2)], ['Peak detection BPS', optionalNumber(traffic.bps, 1)],
        ['Investigation packets', optionalNumber(traffic.packets)], ['Investigation bytes', traffic.bytes === null || traffic.bytes === undefined ? '-' : securityBytes(traffic.bytes)],
        ['Investigation flows', optionalNumber(traffic.flows)],
        ['Source count', optionalNumber(traffic.source_count)], ['ASN diversity', optionalNumber(traffic.asn_diversity)]
      ])}<h4>Metric provenance / time window</h4>${detailGrid([
        ['Detection PPS scope', provenanceWindow(provenance.pps)], ['Detection BPS scope', provenanceWindow(provenance.bps)],
        ['Investigation packets scope', provenanceWindow(provenance.packets)], ['Investigation bytes scope', provenanceWindow(provenance.bytes)],
        ['Investigation window', `${dateTime(traffic.investigation_window?.first_seen)} → ${dateTime(traffic.investigation_window?.last_seen)}${traffic.investigation_window?.window_seconds === null || traffic.investigation_window?.window_seconds === undefined ? '' : ` · ${number(traffic.investigation_window.window_seconds, 3)} s`}`]
      ])}<p class="subtle">Peak/detection rates and investigation volume are retained from different scopes and must not be multiplied as if they covered the same time window.</p>
        ${renderSecurityDistribution(traffic.protocols, 'Protocol distribution')}${renderSecurityDistribution(traffic.ports, 'Destination ports')}</section>
      <section id="campaign-sources">${renderSecuritySources(payload.top_sources || [], true)}</section>
      <section id="campaign-asn"><h3>ASN DISTRIBUTION — TOP SOURCES SNAPSHOT</h3>${detailGrid([
        ['Total campaign ASNs', optionalNumber(asnContext.total_campaign_asns)], ['ASNs represented in snapshot', optionalNumber(asnContext.represented_asns)],
        ['Sources represented in snapshot', optionalNumber(asnContext.represented_sources)]
      ])}${renderCampaignAsnDistribution(payload.asn_distribution)}
        <p class="subtle">${asnContext.complete_campaign_distribution ? 'Distribuição completa persistida da campaign.' : 'Percentuais calculados somente sobre as origens presentes no snapshot persistido de Top Sources; não representam todos os ASNs da campaign.'}</p></section>
      <section id="campaign-intel"><h3>THREAT INTELLIGENCE</h3>${renderCampaignThreatIntel(campaign)}</section>
      <section id="campaign-events"><h3>EVENTOS CORRELACIONADOS</h3>${renderCampaignEvents(payload.correlated_events)}</section>
      <section id="campaign-evidence"><h3>EVIDÊNCIAS DE DETECÇÃO / CORRELAÇÃO</h3><p class="subtle score-semantics" title="${esc(evidence.detector_score_semantics || '')}">${esc(evidence.detector_score_semantics || 'O score do detector reflete critérios locais de detecção, não certeza probabilística.')}</p>${detailGrid(Object.entries(evidence.correlation_features || {}))}
        <h4>Detectores contribuintes</h4>${investigationList((evidence.contributing_vectors || []).map(item => `${item.detector || '-'} · ${item.attack_type || '-'} · score ${optionalNumber(item.score)} · ${item.source || 'distribuída'} → ${item.target || '-'}`))}</section>
      <section id="campaign-ai"><h3>ANÁLISE POR IA DA CAMPANHA</h3>${renderCampaignAiInvestigation(campaign, aiState)}</section>`;
    root.lucide?.createIcons();
  }

  async function openSecurityCampaign(campaignId) {
    currentSecurityEventId = null;
    currentSecurityCampaignId = String(campaignId);
    const drawer = document.getElementById('securityEventDrawer');
    drawer.hidden = false;
    drawer.setAttribute('aria-hidden', 'false');
    document.body.classList.add('security-event-drawer-open');
    setInvestigationHeading('Investigação da campanha', `Investigação da campanha · ${campaignId}`);
    document.getElementById('securityEventDrawerStatus').textContent = 'Carregando investigação da campanha...';
    const base = `/api/security/campaigns/${encodeURIComponent(campaignId)}`;
    const [campaignResult, aiResult] = await Promise.allSettled([apiRequest(base), apiRequest(`${base}/ai-analysis`)]);
    if (campaignResult.status === 'rejected') throw campaignResult.reason;
    const payload = campaignResult.value;
    const aiState = aiResult.status === 'fulfilled' ? aiResult.value : {
      enabled: true,
      configured: true,
      error: `Estado da IA indisponível: ${aiResult.reason?.message || 'falha ao carregar'}`,
    };
    document.getElementById('securityEventDrawerStatus').textContent = aiResult.status === 'fulfilled' ? '' : aiState.error;
    renderSecurityCampaignInvestigation(payload, aiState);
  }

  function renderLegacySecurityAnomalyDetail(item) {
    const available = entries => entries.filter(([, value]) => value !== null && value !== undefined && value !== '');
    const anomalyId = item.id;
    const mitigationId = item._mitigation_anomaly_id || item.id;
    setInvestigationHeading('Legacy anomaly', `Legacy anomaly #${anomalyId}`);
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
    currentSecurityCampaignId = null;
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
    securityTrafficChart?.dispose();
    securityTrafficChart = null;
    currentSecurityEvent = null;
    currentSecuritySources = [];
    currentSecurityEventId = null;
    currentSecurityCampaignId = null;
  }

  async function securityAction(button) {
    const action = button.dataset.securityAction;
    if (action === 'close') return closeSecurityEvent();
    const eventId = button.dataset.eventId || currentSecurityEventId;
    if (action === 'open') return openSecurityEventInvestigation(eventId);
    if (action === 'open-in-threat-intel') {
      if (typeof showView === 'function') showView('threat-intelligence');
      return;
    }
    button.disabled = true;
    try {
      if (action === 'analyze' || action === 'reanalyze') {
        document.getElementById('securityEventDrawerStatus').textContent = 'Analisando evidências estruturadas...';
        await apiRequest(`/api/security/events/${eventId}/ai-analysis${action === 'reanalyze' ? '?force=true' : ''}`, { method: 'POST' });
      } else if (action === 'evidence') {
        document.getElementById('securityEventDrawerStatus').textContent = 'Carregando amostra agregada limitada...';
        const evidence = await apiRequest(`/api/security/events/${eventId}/evidence?sample_limit=100`);
        renderAggregatedEvidence(evidence);
        document.getElementById('securityEventDrawerStatus').textContent = '';
        return;
      } else if (action === 'status') {
        const endpoints = { benign: 'mark-benign', confirmed: 'mark-confirmed', investigating: 'investigating' };
        await apiRequest(`/api/security/events/${eventId}/${endpoints[button.dataset.status]}`, { method: 'POST' });
      }
      await openSecurityEventInvestigation(eventId);
      await loadWorkspace();
    } finally {
      button.disabled = false;
    }
  }

  async function campaignAction(button) {
    const action = button.dataset.campaignAction;
    const campaignId = button.dataset.campaignId || currentSecurityCampaignId;
    if (!campaignId) return;
    if (action === 'open') {
      openSecurityCampaign(campaignId).catch(error => { document.getElementById('securityEventDrawerStatus').textContent = error.message; });
      return;
    }
    if (!['analyze', 'reanalyze'].includes(action)) return;
    button.disabled = true;
    try {
      document.getElementById('securityEventDrawerStatus').textContent = 'Analisando evidências da campanha...';
      const suffix = action === 'reanalyze' ? '?force=true' : '';
      await apiRequest(`/api/security/campaigns/${encodeURIComponent(campaignId)}/ai-analysis${suffix}`, { method: 'POST' });
      await openSecurityCampaign(campaignId);
    } catch (error) {
      try {
        await openSecurityCampaign(campaignId);
      } catch (_reloadError) {
        // Preserve the provider error below even if refreshing the persisted attempt also fails.
      }
      const providerMessage = error?.payload?.detail?.message || error?.payload?.error_message || error?.message || 'Análise de IA indisponível.';
      document.getElementById('securityEventDrawerStatus').textContent = providerMessage;
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
    setMapMeta('Infraestrutura hostil observada', 'Pontos agregados dos provedores externos; detalhes analíticos permanecem nas tabelas', 'Infraestrutura hostil', 'IPs');
    map?.setLoading('Carregando indicadores geográficos...');
    const payload = await apiRequest(`/api/threat-intelligence/map?${query}`);
    map?.setData(
      { nodes: mapNodes(payload.items, payload.group_by || groupBy), metric: 'flows', group_by: payload.group_by || groupBy },
      { metric: 'flows', mode: 'flows', visualization: 'points', groupBy: payload.group_by || groupBy, fit: true }
    );
    setPanelStatus('threatMapStatus', `Mapa atualizado em ${new Date().toLocaleTimeString('pt-BR')}.`);
  }

  function renderSecurityCoverage(summary) {
    const element = document.getElementById('secMapCoverage');
    if (!element) return;
    const s = summary || {};
    element.innerHTML = `<div class="threat-map-coverage__stats">
      <span><strong>Eventos:</strong> ${number(s.total_events)}</span>
      <span><strong>No mapa:</strong> ${number(s.located_events)} (${number(s.located_percent, 1)}%)</span>
      <span><strong>Internos/CGNAT:</strong> ${number(s.private_or_internal)} + ${number(s.cgnat_or_shared)}</span>
      <span><strong>GeoIP ausente:</strong> ${number(s.unlocated_public)} + ${number(s.missing_geo)}</span>
      <span><strong>Ambíguos:</strong> ${number(s.ambiguous_context)}</span>
    </div>
    <div class="threat-map-coverage__breakdown" title="${esc(JSON.stringify(s.unlocated_breakdown || {}))}">
      ${number(s.total_events - s.located_events)} evento(s) não exibidos no mapa — passe o mouse para ver o detalhamento.
    </div>`;
  }

  async function loadSecurityMap() {
    const groupBy = document.getElementById('secMapGroupFilter').value || 'country';
    const query = new URLSearchParams({
      group_by: groupBy,
      period: document.getElementById('secMapPeriodFilter').value || '24h',
      campaign: document.getElementById('secMapCampaignFilter').value || 'all',
      ai_status: document.getElementById('secMapAiFilter').value || 'all',
      direction: document.getElementById('secMapDirectionFilter').value || 'all',
      context: document.getElementById('secMapContextFilter').value || 'all'
    });
    const severity = document.getElementById('secMapSeverityFilter').value;
    const verdict = document.getElementById('secMapVerdictFilter').value;
    const attackType = document.getElementById('secMapTypeFilter').value;
    const status = document.getElementById('secMapStatusFilter').value;
    if (severity) query.set('severity', severity);
    if (verdict) query.set('verdict', verdict);
    if (attackType) query.set('attack_type', attackType);
    if (status) query.set('status', status);
    const map = ensureMap();
    setMapMeta('Ameaças detectadas', 'Origem (inbound) e destino externo (outbound) · determinístico, sem IA', 'Situação de segurança', 'eventos');
    map?.setLoading('Carregando situação de segurança...');
    const payload = await apiRequest(`/api/threat-intelligence/security-map?${query}`);
    map?.setData(
      { nodes: securityMapNodes(payload.points), metric: 'flows', group_by: groupBy },
      { metric: 'flows', mode: 'flows', visualization: 'points', groupBy, fit: true }
    );
    const summary = payload.summary || {};
    renderSecurityCoverage(summary);
    setPanelStatus('threatMapStatus', `${number(summary.total_events)} evento(s) · ${number(summary.located_events)} no mapa (${number(summary.located_percent, 1)}%) · ${number(summary.critical_after)} de ${number(summary.critical_total)} crítico(s) localizados · atualizado em ${new Date().toLocaleTimeString('pt-BR')}.`);
  }

  function setMapLayer(layer) {
    const security = layer === 'security';
    const securityButton = document.getElementById('threatLayerSecurity');
    const infraButton = document.getElementById('threatLayerInfra');
    document.getElementById('threatSecurityFilters').hidden = !security;
    document.getElementById('threatInfraFilters').hidden = security;
    securityButton?.classList.toggle('btn-primary', security);
    securityButton?.classList.toggle('btn-outline-secondary', !security);
    securityButton?.setAttribute('aria-pressed', String(security));
    infraButton?.classList.toggle('btn-primary', !security);
    infraButton?.classList.toggle('btn-outline-secondary', security);
    infraButton?.setAttribute('aria-pressed', String(!security));
    const task = security ? loadSecurityMap() : loadMap();
    return task.catch(error => {
      setPanelStatus('threatMapStatus', `Erro ao carregar mapa: ${error.message}`, true);
      ensureMap()?.setError('Não foi possível carregar o mapa.');
    });
  }

  function applySecurityPreset(preset) {
    const period = document.getElementById('secMapPeriodFilter');
    const severity = document.getElementById('secMapSeverityFilter');
    const verdict = document.getElementById('secMapVerdictFilter');
    const status = document.getElementById('secMapStatusFilter');
    const ai = document.getElementById('secMapAiFilter');
    const direction = document.getElementById('secMapDirectionFilter');
    const context = document.getElementById('secMapContextFilter');
    if (preset === 'recent') {
      period.value = '30m'; severity.value = ''; verdict.value = ''; status.value = ''; ai.value = 'all';
    } else if (preset === 'critical') {
      period.value = '24h'; severity.value = 'CRITICAL'; verdict.value = ''; status.value = ''; ai.value = 'all';
    } else if (preset === 'confirmed') {
      period.value = '24h'; severity.value = ''; verdict.value = 'CONFIRMED_ATTACK'; status.value = ''; ai.value = 'all';
    } else if (preset === 'analyzing') {
      period.value = '24h'; severity.value = ''; verdict.value = ''; status.value = 'active'; ai.value = 'not_analyzed';
    } else {
      period.value = '24h'; severity.value = ''; verdict.value = ''; status.value = ''; ai.value = 'all';
    }
    if (direction) direction.value = 'all';
    if (context) context.value = 'all';
    return loadSecurityMap();
  }

  function renderSecuritySummary(payload) {
    if (!payload) return;
    document.getElementById('secOverviewAnalyzed').textContent = number(payload.analyzed);
    document.getElementById('secOverviewDetections').textContent = number(payload.detections);
    document.getElementById('secOverviewSuspicious').textContent = number(payload.suspicious);
    document.getElementById('secOverviewEvents').textContent = number(payload.security_events);
    document.getElementById('secOverviewCritical').textContent = number(payload.critical);
    document.getElementById('secOverviewHigh').textContent = number(payload.high);
    document.getElementById('secOverviewCorroborated').textContent = number(payload.corroborated);
    document.getElementById('secOverviewEligible').textContent = number(payload.eligible_for_mitigation);
    document.getElementById('secOverviewMitigated').textContent = number(payload.mitigated);
    const pipeline = document.getElementById('secOverviewPipeline');
    if (pipeline) {
      pipeline.textContent = `Pipeline (janela ${number(payload.window_minutes)} min): ${number(payload.analyzed)} analisados → ${number(payload.detections)} detecções → ${number(payload.suspicious)} suspeitos → ${number(payload.security_events)} eventos → ${number(payload.corroborated)} corroborados → ${number(payload.mitigated)} mitigados · ${esc(payload.threat_score_mode || 'shadow')}`;
    }
    document.getElementById('secOverviewStatus').textContent = `Janela de ${number(payload.window_minutes)} min · atualizado em ${new Date().toLocaleTimeString('pt-BR')}.`;
  }

  async function fetchSecuritySummary() {
    const payload = await apiRequest('/api/security/summary?window=60');
    renderSecuritySummary(payload);
    return payload;
  }

  function renderThreatScore(event) {
    const score = event?.threat_score;
    if (!score || score.score === undefined || score.score === null) return '';
    const components = (score.components || []).map(component => `+${number(component.points)} ${esc(component.label)}`).join(' ');
    const decision = score.shadow_decision || '';
    const decisionLabel = decision === 'WOULD_BLOCK' ? 'seria bloqueado' : decision === 'WOULD_NOT_BLOCK' ? 'não seria bloqueado' : decision;
    return `<div class="security-threat-score security-score-block">
      <h4>Threat Score</h4>
      <div><strong>${number(score.score)}/100</strong> <span class="threat-score-band">${esc(score.band)}</span> <span class="subtle">(${esc(score.mode || 'shadow')})</span></div>
      <div class="subtle">Mede risco/prioridade contextual (consultivo).</div>
      ${decision ? `<div class="subtle">Mitigation candidate · ${esc(decisionLabel)}${score.decision_reason ? ` · ${esc(score.decision_reason)}` : ''}</div>` : ''}
      ${components ? `<div class="subtle">${components}</div>` : ''}
      <div class="subtle">Advisory only — nenhuma mitigação executada.</div>
    </div>`;
  }

  let securityEventsEtag = '';
  let lastSecurityEventsPayload = null;

  async function fetchSecurityEvents() {
    if (securityEventsRequestPromise) return securityEventsRequestPromise;
    const headers = securityEventsEtag ? { 'If-None-Match': securityEventsEtag } : {};
    securityEventsRequestPromise = apiRequest('/api/security/events?limit=200', { headers })
      .then(payload => {
        if (payload && payload.__notModified) {
          const cached = lastSecurityEventsPayload || payload;
          Object.defineProperty(cached, '__unchanged', { value: true, configurable: true });
          return cached;
        }
        securityEventsEtag = (payload && payload.__etag) || '';
        lastSecurityEventsPayload = payload;
        return payload;
      })
      .finally(() => { securityEventsRequestPromise = null; });
    return securityEventsRequestPromise;
  }

  function configureSecurityEventsPolling(payload = {}) {
    const requested = Number(payload.ui_refresh_seconds || 10);
    const configured = Number.isFinite(requested) ? Math.max(5, Math.min(15, requested)) : 10;
    if (configured === securityEventsPollingSeconds) return;
    securityEventsPollingSeconds = configured;
    if (securityEventsPollingTimer) {
      root.clearInterval(securityEventsPollingTimer);
      securityEventsPollingTimer = null;
      startSecurityEventsPolling();
    }
  }

  function startSecurityEventsPolling() {
    if (securityEventsPollingTimer) return;
    securityEventsPollingTimer = root.setInterval(() => {
      if (document.visibilityState !== 'visible') return;
      refreshSecurityEventsOnly().catch(() => { /* erro já exibido somente no painel */ });
    }, securityEventsPollingSeconds * 1000);
  }

  function stopSecurityEventsPolling() {
    if (!securityEventsPollingTimer) return;
    root.clearInterval(securityEventsPollingTimer);
    securityEventsPollingTimer = null;
  }

  async function refreshSecurityEventsOnly() {
    setPanelStatus('threatVectorsStatus', 'Atualizando Security Events...');
    try {
      const payload = await fetchSecurityEvents();
      if (payload && payload.__unchanged) {
        setPanelStatus('threatVectorsStatus', `Sem alterações em ${new Date().toLocaleTimeString('pt-BR')} · polling ${securityEventsPollingSeconds} s.`);
        return payload;
      }
      renderVectors(payload);
      configureSecurityEventsPolling(payload);
      fetchSecuritySummary().catch(() => { /* resumo é não-bloqueante */ });
      setPanelStatus('threatVectorsStatus', `Atualizado em ${new Date().toLocaleTimeString('pt-BR')} · polling ${securityEventsPollingSeconds} s.`);
      root.lucide?.createIcons();
      return payload;
    } catch (error) {
      setPanelStatus('threatVectorsStatus', `Erro ao carregar Attack Vectors: ${error.message}`, true);
      throw error;
    }
  }

  async function loadWorkspace() {
    if (loading) return;
    loading = true;
    document.getElementById('threatWorkspaceStatus').textContent = 'Atualizando inteligência e detecções...';
    try {
      const requests = await Promise.allSettled([
        apiRequest('/api/threat-intelligence/providers'),
        fetchSecurityEvents(),
        apiRequest('/api/threat-engine/campaigns?limit=100'),
        apiRequest('/api/threat-engine/policy-decisions?limit=200')
      ]);
      const panels = [
        { name: 'Threat Intelligence', status: 'threatProvidersStatus', render: renderProviders },
        { name: 'Attack Vectors', status: 'threatVectorsStatus', render: renderVectors },
        { name: 'Campaigns', status: 'threatCampaignsStatus', render: renderCampaigns },
        { name: 'Policy Decisions', status: 'threatDecisionsStatus', render: renderDecisions }
      ];
      const failures = [];
      requests.forEach((result, index) => {
        const panel = panels[index];
        if (result.status === 'fulfilled') {
          panel.render(result.value);
          if (panel.name === 'Attack Vectors') {
            configureSecurityEventsPolling(result.value);
            startSecurityEventsPolling();
          }
          setPanelStatus(panel.status, `Atualizado em ${new Date().toLocaleTimeString('pt-BR')}${panel.name === 'Attack Vectors' ? ` · polling ${securityEventsPollingSeconds} s` : ''}.`);
        } else {
          failures.push(panel.name);
          setPanelStatus(panel.status, `Erro ao carregar ${panel.name}: ${result.reason?.message || 'indisponível'}`, true);
        }
      });
      try {
        await loadSecurityMap();
      } catch (error) {
        failures.push('Mapa de Threat Intelligence');
        setPanelStatus('threatMapStatus', `Erro ao carregar mapa: ${error.message}`, true);
        ensureMap()?.setError('Não foi possível carregar o mapa de Threat Intelligence.');
      }
      try {
        await fetchSecuritySummary();
      } catch (error) {
        document.getElementById('secOverviewStatus').textContent = `Falha ao carregar resumo: ${error.message}`;
      }
      document.getElementById('threatWorkspaceStatus').textContent = failures.length
        ? `Atualização parcial: ${failures.join(', ')} indisponível(is). Os demais painéis permanecem atualizados.`
        : `Atualizado em ${new Date().toLocaleTimeString('pt-BR')}.`;
      root.lucide?.createIcons();
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
    const sourceSort = event.target.closest('[data-security-source-sort]');
    if (sourceSort) {
      event.preventDefault();
      const sort = sourceSort.dataset.securitySourceSort || 'packets';
      const rows = document.getElementById('securityEventSourceRows');
      if (rows) rows.innerHTML = sourceTableRows(currentSecuritySources, sort);
      sourceSort.parentElement?.querySelectorAll('[data-security-source-sort]').forEach(button => {
        button.classList.toggle('btn-secondary', button === sourceSort);
        button.classList.toggle('btn-outline-secondary', button !== sourceSort);
      });
      return;
    }
    const legacyAction = event.target.closest('[data-legacy-security-action]');
    if (legacyAction) {
      event.stopPropagation();
      legacySecurityAction(legacyAction).catch(error => { document.getElementById('securityEventDrawerStatus').textContent = error.message; });
      return;
    }
    const campaignActionButton = event.target.closest('[data-campaign-action]');
    if (campaignActionButton) {
      event.stopPropagation();
      campaignAction(campaignActionButton).catch(error => { document.getElementById('securityEventDrawerStatus').textContent = error.message; });
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
      openSecurityEventInvestigation(row.dataset.securityEventId).catch(error => { document.getElementById('threatWorkspaceStatus').textContent = error.message; });
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
    document.getElementById('applyThreatFiltersButton')?.addEventListener('click', () => loadMap().catch(error => {
      setPanelStatus('threatMapStatus', `Erro ao carregar mapa: ${error.message}`, true);
      ensureMap()?.setError('Não foi possível carregar o mapa de Threat Intelligence.');
    }));
    document.getElementById('applySecMapFiltersButton')?.addEventListener('click', () => loadSecurityMap().catch(error => {
      setPanelStatus('threatMapStatus', `Erro ao carregar mapa: ${error.message}`, true);
      ensureMap()?.setError('Não foi possível carregar o mapa de situação de segurança.');
    }));
    document.getElementById('threatLayerSecurity')?.addEventListener('click', () => setMapLayer('security'));
    document.getElementById('threatLayerInfra')?.addEventListener('click', () => setMapLayer('infra'));
    document.querySelectorAll('.sec-map-preset').forEach(button => {
      button.addEventListener('click', () => applySecurityPreset(button.dataset.preset).catch(error => {
        setPanelStatus('threatMapStatus', `Erro ao carregar mapa: ${error.message}`, true);
      }));
    });
    document.getElementById('runThreatEngineButton')?.addEventListener('click', async () => {
      const button = document.getElementById('runThreatEngineButton');
      button.disabled = true;
      try { await apiRequest('/api/threat-engine/run', { method: 'POST' }); await loadWorkspace(); }
      catch (error) { document.getElementById('threatWorkspaceStatus').textContent = error.message; }
      finally { button.disabled = false; }
    });
  });

  root.loadThreatIntelligenceWorkspace = loadWorkspace;
  root.refreshSecurityEventsOnly = refreshSecurityEventsOnly;
  root.startThreatIntelligencePolling = startSecurityEventsPolling;
  root.stopThreatIntelligencePolling = stopSecurityEventsPolling;
  root.openSecurityEventInvestigation = eventId => openSecurityEventInvestigation(eventId).catch(error => {
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
