(function dashboardVisualizationsFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardVisualizations = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardVisualizations() {
  'use strict';

  const CALCULATIONS = Object.freeze([
    'current',
    'last',
    'last_not_null',
    'mean',
    'max',
    'min',
    'total',
    'difference'
  ]);
  const VISUALIZATIONS_BY_DATA_KIND = Object.freeze({
    ranking_snapshot: Object.freeze([
      'table',
      'horizontal_bar',
      'vertical_bar',
      'pie',
      'donut',
      'bar_gauge',
      'chart_table',
      'stat'
    ]),
    timeseries: Object.freeze(['line', 'area', 'time_bars', 'line_area', 'stat']),
    stat: Object.freeze(['stat']),
    table: Object.freeze(['table']),
    status: Object.freeze(['status', 'table', 'stat'])
  });
  const VISUALIZATION_ALIASES = Object.freeze({
    bar: 'vertical_bar',
    number: 'stat',
    stacked_area: 'area'
  });
  const VISUAL_CONFIG_KEYS = new Set([
    'appearance',
    'axis_show_negative_sign',
    'calculation',
    'data_kind',
    'field_config',
    'legend_calculation',
    'palette',
    'show_labels',
    'show_legend',
    'traffic_orientation',
    'unit',
    'visualization',
    'visualization_kind',
    'decimals'
  ]);

  function finiteNumber(value, fallback = 0) {
    if (value === null || value === undefined || value === '') return fallback;
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
  }

  function dataKindForWidget(widget = {}) {
    return widget.config?.data_kind || {
      top_n: 'ranking_snapshot',
      timeseries: 'timeseries',
      kpi: 'stat',
      recent_events: 'table',
      status_list: 'status'
    }[widget.type] || 'table';
  }

  function visualizationChoices(dataKind) {
    return [...(VISUALIZATIONS_BY_DATA_KIND[dataKind] || ['table'])];
  }

  function visualizationKind(widget = {}) {
    const dataKind = dataKindForWidget(widget);
    const candidate = String(
      widget.config?.visualization_kind
      || widget.visualization?.visualization_kind
      || widget.visualization?.type
      || widget.config?.visualization
      || (dataKind === 'timeseries' ? 'line' : dataKind === 'stat' ? 'stat' : 'table')
    ).toLowerCase();
    const normalized = VISUALIZATION_ALIASES[candidate] || candidate;
    const choices = visualizationChoices(dataKind);
    return choices.includes(normalized) ? normalized : choices[0];
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

  function dataQuerySignature(widget = {}) {
    const config = Object.fromEntries(
      Object.entries(widget.config || {}).filter(([key]) => !VISUAL_CONFIG_KEYS.has(key))
    );
    return JSON.stringify(stableValue({
      type: widget.type,
      config,
      filters: widget.filters || [],
      inheritance: widget.inheritance || {},
      use_global_filters: widget.use_global_filters !== false,
      use_global_time_range: widget.use_global_time_range !== false,
      custom_time_range: widget.use_global_time_range === false
        ? widget.custom_time_range || {}
        : {}
    }));
  }

  function normalizeRankingPayload(payload = {}) {
    const rawItems = Array.isArray(payload.items) ? payload.items : [];
    const items = rawItems.map((item, index) => {
      const value = finiteNumber(item.value ?? item[payload.metric], 0);
      return {
        ...item,
        rank: Math.max(1, Math.trunc(finiteNumber(item.rank, index + 1))),
        key: String(item.key ?? item.label ?? item.name ?? '-'),
        label: String(item.label ?? item.key ?? item.name ?? '-'),
        value,
        percent: finiteNumber(item.percent ?? item.percentage, NaN),
        metadata: item.metadata && typeof item.metadata === 'object'
          ? { ...item.metadata }
          : {}
      };
    });
    const total = finiteNumber(
      payload.total,
      items.reduce((sum, item) => sum + item.value, 0)
    );
    items.forEach(item => {
      if (!Number.isFinite(item.percent)) {
        item.percent = total ? item.value / total * 100 : 0;
      }
      item.percent = Math.round(item.percent * 100) / 100;
    });
    return {
      ...payload,
      kind: 'ranking',
      data_kind: 'ranking_snapshot',
      calculation: payload.calculation || 'current',
      total,
      items
    };
  }

  function rankingDataset(payload = {}) {
    const normalized = normalizeRankingPayload(payload);
    return {
      dimensions: ['rank', 'key', 'label', 'value', 'percent'],
      source: normalized.items.map(item => ({
        rank: item.rank,
        key: item.key,
        label: item.label,
        value: item.value,
        percent: item.percent
      })),
      items: normalized.items,
      total: normalized.total,
      calculation: normalized.calculation,
      metric: normalized.metric
    };
  }

  function groupRankingItems(items = [], sliceLimit = 8) {
    const source = Array.isArray(items) ? items : [];
    const limit = clamp(Math.trunc(finiteNumber(sliceLimit, 8)), 2, 20);
    if (source.length <= limit) return source.map(item => ({ ...item }));
    const visibleCount = limit - 1;
    const visible = source.slice(0, visibleCount).map(item => ({ ...item }));
    const remaining = source.slice(visibleCount);
    visible.push({
      rank: limit,
      key: '__others__',
      label: 'Outros',
      value: remaining.reduce((sum, item) => sum + finiteNumber(item.value, 0), 0),
      percent: remaining.reduce((sum, item) => sum + finiteNumber(item.percent, 0), 0),
      metadata: {
        grouped_items: remaining.length,
        grouped_keys: remaining.map(item => item.key)
      }
    });
    return visible;
  }

  function pointValue(point) {
    if (Array.isArray(point)) return finiteNumber(point[1], NaN);
    return finiteNumber(point?.value, NaN);
  }

  function calculatePoints(points, calculation = 'last_not_null') {
    const rawValues = (Array.isArray(points) ? points : []).map(pointValue);
    if (calculation === 'last') {
      const finalValue = rawValues[rawValues.length - 1];
      return Number.isFinite(finalValue) ? finalValue : null;
    }
    const values = rawValues.filter(Number.isFinite);
    if (!values.length) return null;
    if (calculation === 'last_not_null') {
      return values[values.length - 1];
    }
    if (calculation === 'mean') {
      return values.reduce((sum, value) => sum + value, 0) / values.length;
    }
    if (calculation === 'max') return Math.max(...values);
    if (calculation === 'min') return Math.min(...values);
    if (calculation === 'total') {
      return values.reduce((sum, value) => sum + value, 0);
    }
    if (calculation === 'difference') return values[values.length - 1] - values[0];
    return values[values.length - 1];
  }

  function normalizedFieldConfig(config = {}, appearance = {}) {
    const source = config.field_config && typeof config.field_config === 'object'
      ? config.field_config
      : {};
    const defaults = source.defaults && typeof source.defaults === 'object'
      ? source.defaults
      : {};
    return {
      defaults: {
        unit: defaults.unit || config.unit || config.metric || 'short',
        decimals: defaults.decimals ?? 'auto',
        color: defaults.color || { mode: 'palette-classic' },
        line_width: clamp(finiteNumber(defaults.line_width, appearance.line_width || 2), 1, 5),
        fill_opacity: clamp(
          finiteNumber(defaults.fill_opacity, finiteNumber(appearance.area_opacity, 0.22) * 100),
          0,
          100
        ),
        show_points: ['auto', 'always', 'never'].includes(defaults.show_points)
          ? defaults.show_points
          : 'never',
        null_value: ['null', 'zero', 'connected'].includes(defaults.null_value)
          ? defaults.null_value
          : 'null',
        min: defaults.min === null || defaults.min === undefined || defaults.min === ''
          ? null
          : finiteNumber(defaults.min, null),
        max: defaults.max === null || defaults.max === undefined || defaults.max === ''
          ? null
          : finiteNumber(defaults.max, null),
        smooth: defaults.smooth === undefined
          ? appearance.smooth_lines !== false
          : Boolean(defaults.smooth),
        stacked: Boolean(defaults.stacked)
      },
      overrides: Array.isArray(source.overrides) ? source.overrides : []
    };
  }

  function matcherMatches(matcher = {}, series = {}, metric = '') {
    const type = String(matcher.type || '').toLowerCase();
    const expected = String(matcher.value || '');
    if (type === 'field_name') return [series.key, series.name].includes(expected);
    if (type === 'direction') return String(series.direction || series.key) === expected;
    if (type === 'metric') return String(metric) === expected;
    if (type === 'regex') {
      try {
        return new RegExp(expected).test(String(series.name || series.key || ''));
      } catch {
        return false;
      }
    }
    return false;
  }

  function fieldProperties(series, metric, config = {}, appearance = {}) {
    const fieldConfig = normalizedFieldConfig(config, appearance);
    const direction = String(series.direction || series.key || '').toLowerCase();
    const defaults = {
      color: direction === 'upload'
        ? appearance.upload_color
        : direction === 'download'
          ? appearance.download_color
          : appearance.bar_color,
      line_width: fieldConfig.defaults.line_width,
      fill_opacity: fieldConfig.defaults.fill_opacity,
      smooth: fieldConfig.defaults.smooth,
      visible: true,
      negative_y: false
    };
    fieldConfig.overrides.forEach(override => {
      if (matcherMatches(override.matcher, series, metric)) {
        Object.assign(defaults, override.properties || {});
      }
    });
    return defaults;
  }

  function buildTrafficModel(payload = {}, config = {}, appearance = {}) {
    const orientation = ['positive_both', 'split_zero', 'stacked'].includes(
      config.traffic_orientation
    ) ? config.traffic_orientation : 'positive_both';
    const calculation = CALCULATIONS.includes(config.legend_calculation)
      ? config.legend_calculation
      : 'last_not_null';
    const fieldConfig = normalizedFieldConfig(config, appearance);
    const originalSeries = Array.isArray(payload.series) ? payload.series : [];
    let maxAbs = 0;
    const series = originalSeries.map(item => {
      const direction = String(item.direction || item.key || '').toLowerCase();
      const properties = fieldProperties(item, payload.metric, config, appearance);
      const negative = properties.negative_y
        || (orientation === 'split_zero' && direction === 'upload');
      const originalPoints = (item.points || []).map(point => {
        const number = finiteNumber(point.value, NaN);
        return {
          ts: point.ts ?? point.timestamp ?? point.time,
          partial: Boolean(point.partial),
          bucket_duration_seconds: point.bucket_duration_seconds ?? null,
          value: Number.isFinite(number)
            ? Math.abs(number)
            : fieldConfig.defaults.null_value === 'zero'
              ? 0
              : null
        };
      });
      originalPoints.forEach(point => {
        if (Number.isFinite(point.value)) {
          maxAbs = Math.max(maxAbs, Math.abs(point.value));
        }
      });
      const visualPoints = originalPoints.map(point => ({
        ts: point.ts,
        partial: point.partial,
        bucket_duration_seconds: point.bucket_duration_seconds,
        value: Number.isFinite(point.value)
          ? (negative ? -point.value : point.value)
          : null
      }));
      const legendPoints = calculation === 'last_not_null'
        ? originalPoints.filter(point => !point.partial)
        : originalPoints;
      const calculatedLegendValue = calculatePoints(
        legendPoints,
        calculation
      );
      return {
        ...item,
        direction,
        properties,
        negative,
        original_points: originalPoints,
        points: visualPoints,
        legend_value: Number.isFinite(calculatedLegendValue)
          ? Math.abs(calculatedLegendValue)
          : null
      };
    }).filter(item => item.properties.visible !== false);
    const configuredMaximum = Math.max(
      Math.abs(finiteNumber(fieldConfig.defaults.min, 0)),
      Math.abs(finiteNumber(fieldConfig.defaults.max, 0))
    );
    const symmetricMaximum = Math.max(1, maxAbs * 1.08, configuredMaximum);
    return {
      orientation,
      calculation,
      original_series: originalSeries,
      series,
      max_abs: maxAbs,
      y_min: orientation === 'split_zero'
        ? -symmetricMaximum
        : fieldConfig.defaults.min ?? undefined,
      y_max: orientation === 'split_zero'
        ? symmetricMaximum
        : fieldConfig.defaults.max ?? undefined,
      connect_nulls: fieldConfig.defaults.null_value === 'connected',
      stacked: fieldConfig.defaults.stacked || orientation === 'stacked',
      axis_show_negative_sign: Boolean(config.axis_show_negative_sign)
    };
  }

  function latestTimestamp(payload = {}) {
    let latest = '';
    (payload.series || []).forEach(series => {
      (series.points || []).forEach(point => {
        const timestamp = String(point.ts ?? point.timestamp ?? point.time ?? '');
        if (timestamp > latest) latest = timestamp;
      });
    });
    return latest || null;
  }

  function inspectorSnapshot(widget = {}, payload = {}) {
    const normalizedPayload = payload.kind === 'top_n' || payload.kind === 'ranking'
      ? normalizeRankingPayload(payload)
      : payload;
    const model = dataKindForWidget(widget) === 'timeseries'
      ? buildTrafficModel(
        normalizedPayload,
        widget.config || {},
        widget.config?.appearance || {}
      )
      : null;
    return {
      payload: normalizedPayload,
      data_kind: dataKindForWidget(widget),
      calculation: widget.config?.calculation
        || normalizedPayload.calculation
        || (widget.type === 'timeseries' ? 'last_not_null' : 'current'),
      legend_calculation: widget.config?.legend_calculation || 'last_not_null',
      visualization_kind: visualizationKind(widget),
      series_count: Array.isArray(normalizedPayload.series)
        ? normalizedPayload.series.length
        : 0,
      item_count: Array.isArray(normalizedPayload.items)
        ? normalizedPayload.items.length
        : 0,
      last_timestamp: latestTimestamp(normalizedPayload),
      source: normalizedPayload.source || normalizedPayload.meta?.source || null,
      legend_values: model
        ? Object.fromEntries(model.series.map(series => [series.name, series.legend_value]))
        : {},
      config: widget.config || {}
    };
  }

  return Object.freeze({
    CALCULATIONS,
    VISUALIZATIONS_BY_DATA_KIND,
    dataKindForWidget,
    visualizationChoices,
    visualizationKind,
    dataQuerySignature,
    normalizeRankingPayload,
    rankingDataset,
    groupRankingItems,
    calculatePoints,
    normalizedFieldConfig,
    fieldProperties,
    buildTrafficModel,
    latestTimestamp,
    inspectorSnapshot
  });
});
