(function dashboardTimeRangeFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardTimeRange = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardTimeRange() {
  'use strict';

  function finitePositiveInteger(value, fallback = null) {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) return fallback;
    return Math.ceil(number);
  }

  function utcIso(value) {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error('Período personalizado inválido.');
    }
    return parsed.toISOString().replace(/\.\d{3}Z$/, 'Z');
  }

  function formatUtcTimestamp(value, locale = 'pt-BR') {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return String(value || '');
    return new Intl.DateTimeFormat(locale, {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
      timeZone: 'UTC',
      timeZoneName: 'short'
    }).format(parsed);
  }

  function buildRangeContext(selectedValue, customRange = {}) {
    if (String(selectedValue) !== 'custom') {
      const rangeMinutes = finitePositiveInteger(selectedValue);
      if (rangeMinutes === null) throw new Error('Período global inválido.');
      return { range_minutes: rangeMinutes };
    }
    if (!customRange.start || !customRange.end) {
      throw new Error('Informe o início e o fim do período personalizado.');
    }
    const start = utcIso(customRange.start);
    const end = utcIso(customRange.end);
    const durationMs = new Date(end).getTime() - new Date(start).getTime();
    if (durationMs <= 0) {
      throw new Error('O início precisa ser menor que o fim.');
    }
    return {
      start,
      end,
      range_minutes: Math.ceil(durationMs / 60000)
    };
  }

  function stableValue(value) {
    if (Array.isArray(value)) return value.map(stableValue);
    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.keys(value).sort().map(key => [key, stableValue(value[key])])
      );
    }
    return value;
  }

  function contextSignature(context = {}) {
    return JSON.stringify(stableValue(context));
  }

  function widgetCacheKey(dashboardId, widgetId, dataSignature, context = {}) {
    return [
      'gmjflow_widget_data',
      finitePositiveInteger(dashboardId, 0),
      finitePositiveInteger(widgetId, 0),
      encodeURIComponent(String(dataSignature || '')),
      encodeURIComponent(contextSignature(context))
    ].join('_');
  }

  function createRequestGate() {
    let revision = 0;
    let signature = '';
    return Object.freeze({
      activate(context = {}) {
        const nextSignature = contextSignature(context);
        const changed = nextSignature !== signature;
        if (changed) {
          revision += 1;
          signature = nextSignature;
        }
        return Object.freeze({ revision, signature, changed });
      },
      isCurrent(token) {
        return Boolean(
          token
          && token.revision === revision
          && token.signature === signature
        );
      },
      current() {
        return Object.freeze({ revision, signature, changed: false });
      }
    });
  }

  return Object.freeze({
    buildRangeContext,
    contextSignature,
    formatUtcTimestamp,
    widgetCacheKey,
    createRequestGate
  });
});
