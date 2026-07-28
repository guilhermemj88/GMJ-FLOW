(function dashboardChartsFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardCharts = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardCharts() {
  'use strict';

  const DEFAULT_APPEARANCE = Object.freeze({
    palette_mode: 'default',
    upload_color: '#2563eb',
    download_color: '#16a34a',
    line_width: 2,
    area_opacity: 0.22,
    smooth_lines: true,
    show_area: true,
    show_point_labels: false,
    show_value_labels: false,
    show_legend: true,
    legend_position: 'top',
    axis_label_density: 'auto',
    bar_color: '#0f766e',
    positive_color: '#16a34a',
    negative_color: '#dc2626',
    minimum_slice_label_percent: 3
  });
  const DIRECTION_ORDER = Object.freeze(['upload', 'download']);
  const HEX_COLOR = /^#[0-9a-f]{6}$/i;

  function finiteNumber(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
  }

  function booleanValue(value, fallback) {
    if (value === undefined || value === null || value === '') return fallback;
    if (typeof value === 'string') {
      return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
    }
    return Boolean(value);
  }

  function colorValue(value, fallback) {
    const color = String(value || '').trim();
    return HEX_COLOR.test(color) ? color.toLowerCase() : fallback;
  }

  function normalizeAppearance(value = {}) {
    const source = value && typeof value === 'object' ? value : {};
    const paletteMode = source.palette_mode === 'custom' ? 'custom' : 'default';
    const defaults = DEFAULT_APPEARANCE;
    const useCustomColors = paletteMode === 'custom';
    return {
      palette_mode: paletteMode,
      upload_color: useCustomColors
        ? colorValue(source.upload_color, defaults.upload_color)
        : defaults.upload_color,
      download_color: useCustomColors
        ? colorValue(source.download_color, defaults.download_color)
        : defaults.download_color,
      line_width: clamp(finiteNumber(source.line_width, defaults.line_width), 1, 5),
      area_opacity: clamp(finiteNumber(source.area_opacity, defaults.area_opacity), 0, 1),
      smooth_lines: booleanValue(source.smooth_lines, defaults.smooth_lines),
      show_area: booleanValue(source.show_area, defaults.show_area),
      show_point_labels: booleanValue(
        source.show_point_labels ?? source.show_value_labels,
        defaults.show_point_labels
      ),
      show_value_labels: booleanValue(
        source.show_value_labels ?? source.show_point_labels,
        defaults.show_value_labels
      ),
      show_legend: booleanValue(source.show_legend, defaults.show_legend),
      legend_position: ['top', 'bottom', 'right'].includes(source.legend_position)
        ? source.legend_position
        : defaults.legend_position,
      axis_label_density: ['auto', 'sparse', 'normal', 'dense'].includes(source.axis_label_density)
        ? source.axis_label_density
        : defaults.axis_label_density,
      bar_color: useCustomColors
        ? colorValue(source.bar_color, defaults.bar_color)
        : defaults.bar_color,
      positive_color: useCustomColors
        ? colorValue(source.positive_color, defaults.positive_color)
        : defaults.positive_color,
      negative_color: useCustomColors
        ? colorValue(source.negative_color, defaults.negative_color)
        : defaults.negative_color,
      minimum_slice_label_percent: clamp(
        finiteNumber(
          source.minimum_slice_label_percent,
          defaults.minimum_slice_label_percent
        ),
        0,
        100
      )
    };
  }

  function canonicalMetric(metric) {
    const normalized = String(metric || '').trim().toLowerCase();
    if (['bps', 'bits_s', 'bits_per_second'].includes(normalized)) return 'bits_s';
    if (['pps', 'packets_s', 'packets_per_second'].includes(normalized)) return 'packets_s';
    return normalized || 'count';
  }

  function pointTimestamp(point) {
    return String(point?.ts ?? point?.time ?? point?.timestamp ?? '');
  }

  function consolidateDirectionSeries(series, metric, requestedDirection = 'both') {
    const requested = ['upload', 'download'].includes(requestedDirection)
      ? [requestedDirection]
      : DIRECTION_ORDER;
    const values = new Map(requested.map(direction => [direction, new Map()]));
    (Array.isArray(series) ? series : []).forEach(item => {
      const direction = String(item?.direction || item?.key || '').trim().toLowerCase();
      if (!values.has(direction)) return;
      const points = values.get(direction);
      const itemPoints = new Map();
      (Array.isArray(item.points) ? item.points : []).forEach(point => {
        const timestamp = pointTimestamp(point);
        if (!timestamp) return;
        itemPoints.set(timestamp, finiteNumber(point?.value, 0) || 0);
      });
      itemPoints.forEach((value, timestamp) => {
        points.set(timestamp, (points.get(timestamp) || 0) + value);
      });
    });
    const appearance = DEFAULT_APPEARANCE;
    return requested.map(direction => ({
      key: direction,
      name: direction === 'upload' ? 'Total Upload' : 'Total Download',
      direction,
      metric: canonicalMetric(metric),
      color: direction === 'upload'
        ? appearance.upload_color
        : appearance.download_color,
      points: [...values.get(direction).entries()]
        .sort((left, right) => left[0].localeCompare(right[0]))
        .map(([ts, value]) => ({ ts, value }))
    }));
  }

  function getChartDensityMode(width, height, preference = 'auto') {
    const configured = String(preference || 'auto').toLowerCase();
    if (configured === 'sparse') return 'compact';
    if (configured === 'normal') return 'normal';
    if (configured === 'dense') return 'detailed';
    const safeWidth = Math.max(0, finiteNumber(width, 0));
    const safeHeight = Math.max(0, finiteNumber(height, 0));
    if (safeWidth < 420 || safeHeight < 260) return 'compact';
    if (safeWidth >= 780 && safeHeight >= 420) return 'detailed';
    return 'normal';
  }

  function densitySettings(mode) {
    if (mode === 'compact') {
      return Object.freeze({
        splitNumber: 3,
        fontSize: 10,
        categoryLimit: 5,
        showPointLabels: false,
        compactLegend: true
      });
    }
    if (mode === 'detailed') {
      return Object.freeze({
        splitNumber: 7,
        fontSize: 12,
        categoryLimit: 20,
        showPointLabels: true,
        compactLegend: false
      });
    }
    return Object.freeze({
      splitNumber: 5,
      fontSize: 11,
      categoryLimit: 10,
      showPointLabels: true,
      compactLegend: false
    });
  }

  function truncateCategory(value, maximum = 24) {
    const text = String(value ?? '');
    const limit = Math.max(4, Math.trunc(finiteNumber(maximum, 24)));
    return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
  }

  function replaceChartOption(chart, option) {
    if (!chart || typeof chart.setOption !== 'function') return;
    chart.off?.();
    chart.setOption(option, {
      notMerge: true,
      replaceMerge: ['series', 'xAxis', 'yAxis']
    });
  }

  return Object.freeze({
    DEFAULT_APPEARANCE,
    DIRECTION_ORDER,
    normalizeAppearance,
    canonicalMetric,
    consolidateDirectionSeries,
    getChartDensityMode,
    densitySettings,
    truncateCategory,
    replaceChartOption
  });
});
