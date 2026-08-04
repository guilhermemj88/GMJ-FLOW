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
  const DEFAULT_WIDGET_BREAKPOINTS = Object.freeze({
    stacked: 600,
    wide: 900,
    tiny: 420
  });
  const ACCESSIBLE_SERIES_BASE = Object.freeze([
    '#56b4e9', '#e69f00', '#00c896', '#f0e442', '#4ea1d3',
    '#f4773b', '#cc79a7', '#e5e7eb', '#8dd3c7', '#fb8072'
  ]);
  const HEX_COLOR = /^#[0-9a-f]{6}$/i;

  function finiteNumber(value, fallback) {
    if (value === null || value === undefined || value === '') return fallback;
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

  function hslToHex(hue, saturation, lightness) {
    const h = ((Number(hue) % 360) + 360) % 360;
    const s = clamp(Number(saturation) / 100, 0, 1);
    const l = clamp(Number(lightness) / 100, 0, 1);
    const chroma = (1 - Math.abs(2 * l - 1)) * s;
    const component = chroma * (1 - Math.abs((h / 60) % 2 - 1));
    const offset = l - chroma / 2;
    let rgb;
    if (h < 60) rgb = [chroma, component, 0];
    else if (h < 120) rgb = [component, chroma, 0];
    else if (h < 180) rgb = [0, chroma, component];
    else if (h < 240) rgb = [0, component, chroma];
    else if (h < 300) rgb = [component, 0, chroma];
    else rgb = [chroma, 0, component];
    return `#${rgb.map(value => Math.round((value + offset) * 255)
      .toString(16).padStart(2, '0')).join('')}`;
  }

  function buildDistinctSeriesPalette(size = 50) {
    const maximum = Math.max(1, Math.trunc(finiteNumber(size, 50)));
    const colors = [...ACCESSIBLE_SERIES_BASE];
    let index = 0;
    while (colors.length < maximum) {
      const hue = (19 + index * 137.508) % 360;
      const saturation = [72, 84, 66, 78][index % 4];
      const lightness = [62, 70, 58, 66][Math.floor(index / 4) % 4];
      const color = hslToHex(hue, saturation, lightness);
      if (!colors.includes(color)) colors.push(color);
      index += 1;
    }
    return Object.freeze(colors.slice(0, maximum));
  }

  const DISTINCT_SERIES_PALETTE = buildDistinctSeriesPalette(50);

  function stableSeriesHash(value) {
    const text = String(value ?? '');
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return hash >>> 0;
  }

  function seriesIdentity(value, fallbackIndex = 0) {
    if (value && typeof value === 'object') {
      return String(
        value.key ?? value.name ?? value.label ?? value.group
        ?? `series-${fallbackIndex}`
      );
    }
    return String(value ?? `series-${fallbackIndex}`);
  }

  function assignSeriesColors(values = [], registry = new Map(), palette = DISTINCT_SERIES_PALETTE) {
    const colors = Array.isArray(palette) && palette.length
      ? palette
      : DISTINCT_SERIES_PALETTE;
    const keys = [...new Set(
      (Array.isArray(values) ? values : []).map(seriesIdentity)
    )];
    const assignments = new Map();
    const used = new Set();
    keys.slice().sort().forEach(key => {
      const existing = registry?.get?.(key);
      if (colors.includes(existing) && !used.has(existing)) {
        assignments.set(key, existing);
        used.add(existing);
      }
    });
    keys.filter(key => !assignments.has(key))
      .sort((left, right) => (
        stableSeriesHash(left) - stableSeriesHash(right)
        || left.localeCompare(right)
      ))
      .forEach(key => {
        const initial = stableSeriesHash(key) % colors.length;
        let selected = colors[initial];
        for (let probe = 0; probe < colors.length; probe += 1) {
          const candidate = colors[(initial + probe * 17) % colors.length];
          if (!used.has(candidate)) {
            selected = candidate;
            break;
          }
        }
        assignments.set(key, selected);
        used.add(selected);
        registry?.set?.(key, selected);
      });
    return assignments;
  }

  function colorLuminance(color) {
    if (!HEX_COLOR.test(String(color || ''))) return 0;
    const channels = String(color).slice(1).match(/.{2}/g).map(part => {
      const value = Number.parseInt(part, 16) / 255;
      return value <= 0.03928
        ? value / 12.92
        : ((value + 0.055) / 1.055) ** 2.4;
    });
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  }

  function seriesContrastRatio(left, right = '#0f172a') {
    const first = colorLuminance(left);
    const second = colorLuminance(right);
    return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
  }

  function tooltipNumericValue(item) {
    const value = Array.isArray(item?.value)
      ? item.value[item.value.length - 1]
      : item?.value;
    return finiteNumber(value, 0);
  }

  function sortTooltipRows(rows = []) {
    return (Array.isArray(rows) ? [...rows] : [])
      .sort((left, right) => (
        Math.abs(tooltipNumericValue(right)) - Math.abs(tooltipNumericValue(left))
        || String(left?.seriesName || left?.name || '')
          .localeCompare(String(right?.seriesName || right?.name || ''))
      ));
  }

  function positionFloatingTooltip(point = [], size = {}, options = {}) {
    const gap = Math.max(0, finiteNumber(options.gap, 14));
    const padding = Math.max(0, finiteNumber(options.padding, 8));
    const viewWidth = Math.max(0, finiteNumber(size?.viewSize?.[0], 0));
    const viewHeight = Math.max(0, finiteNumber(size?.viewSize?.[1], 0));
    const contentWidth = Math.max(0, finiteNumber(size?.contentSize?.[0], 0));
    const contentHeight = Math.max(0, finiteNumber(size?.contentSize?.[1], 0));
    const anchorX = finiteNumber(point?.[0], 0);
    const anchorY = finiteNumber(point?.[1], 0);
    let x = anchorX + gap;
    let y = anchorY + gap;
    if (x + contentWidth + padding > viewWidth) x = anchorX - contentWidth - gap;
    if (y + contentHeight + padding > viewHeight) y = anchorY - contentHeight - gap;
    return [
      clamp(x, padding, Math.max(padding, viewWidth - contentWidth - padding)),
      clamp(y, padding, Math.max(padding, viewHeight - contentHeight - padding))
    ];
  }

  function externalTooltipOptions(options = {}) {
    const maxWidth = clamp(finiteNumber(options.maxWidth, 440), 180, 720);
    const maxHeight = clamp(finiteNumber(options.maxHeight, 360), 120, 600);
    return {
      renderMode: 'html',
      appendToBody: true,
      confine: false,
      enterable: true,
      order: 'valueDesc',
      className: 'gmj-dashboard-chart-tooltip',
      position: (point, _params, _dom, _rect, size) => (
        positionFloatingTooltip(point, size, options)
      ),
      extraCssText: [
        `max-width:min(${maxWidth}px,calc(100vw - 16px))`,
        `max-height:min(${maxHeight}px,50vh)`,
        'overflow-x:hidden',
        'overflow-y:auto',
        'white-space:normal',
        'overflow-wrap:anywhere',
        'z-index:10000'
      ].join(';')
    };
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
        itemPoints.set(timestamp, {
          value: finiteNumber(point?.value, null),
          partial: Boolean(point?.partial),
          bucket_duration_seconds: point?.bucket_duration_seconds ?? null
        });
      });
      itemPoints.forEach((point, timestamp) => {
        const current = points.get(timestamp) || {
          values: [],
          partial: false,
          bucket_duration_seconds: null
        };
        if (point.value !== null) current.values.push(point.value);
        current.partial = current.partial || point.partial;
        current.bucket_duration_seconds = point.bucket_duration_seconds
          ?? current.bucket_duration_seconds;
        points.set(timestamp, current);
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
        .map(([ts, point]) => ({
          ts,
          value: point.values.length
            ? point.values.reduce((sum, value) => sum + value, 0)
            : null,
          partial: point.partial,
          bucket_duration_seconds: point.bucket_duration_seconds
        }))
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

  function normalizeWidgetBreakpoints(value = {}) {
    const source = value && typeof value === 'object' ? value : {};
    const stacked = clamp(
      finiteNumber(
        source.stacked ?? source.stack_below ?? source.stacked_below,
        DEFAULT_WIDGET_BREAKPOINTS.stacked
      ),
      320,
      1200
    );
    const wide = clamp(
      finiteNumber(
        source.wide ?? source.wide_from ?? source.wide_min,
        DEFAULT_WIDGET_BREAKPOINTS.wide
      ),
      stacked + 100,
      1800
    );
    const tiny = clamp(
      finiteNumber(
        source.tiny ?? source.hide_secondary_below,
        DEFAULT_WIDGET_BREAKPOINTS.tiny
      ),
      240,
      stacked - 1
    );
    return Object.freeze({ stacked, wide, tiny });
  }

  function getWidgetResponsiveLayout(width, options = {}) {
    const safeWidth = Math.max(0, finiteNumber(width, 0));
    const breakpoints = normalizeWidgetBreakpoints(options.breakpoints);
    const preferredChartRatio = clamp(
      finiteNumber(options.chartRatio, 55),
      25,
      75
    );
    const mode = safeWidth >= breakpoints.wide
      ? 'wide'
      : safeWidth >= breakpoints.stacked
        ? 'medium'
        : 'stacked';
    return Object.freeze({
      mode,
      width: safeWidth,
      breakpoints,
      chartRatio: mode === 'wide'
        ? preferredChartRatio
        : mode === 'medium'
          ? Math.min(40, preferredChartRatio)
          : 100,
      tableDensity: safeWidth < breakpoints.tiny
        ? 'tiny'
        : safeWidth < breakpoints.stacked
          ? 'compact'
          : 'normal'
    });
  }

  function getWidgetContentMetrics(width, height, options = {}) {
    const safeWidth = Math.max(1, finiteNumber(width, 1));
    const safeHeight = Math.max(1, finiteNumber(height, 1));
    const itemCount = Math.max(0, Math.trunc(finiteNumber(options.itemCount, 0)));
    const scale = clamp(
      Math.min(safeWidth / 520, safeHeight / 340),
      0.82,
      1.16
    );
    const fontSize = clamp(13 * scale, 11, 15);
    const labelSize = clamp(12 * scale, 10, 14);
    const gap = clamp(8 * scale, 5, 11);
    const tableHeaderHeight = clamp(31 * scale, 27, 36);
    const availableRowsHeight = Math.max(0, safeHeight - tableHeaderHeight);
    const idealRowHeight = itemCount > 0
      ? availableRowsHeight / itemCount
      : 34 * scale;
    const rowHeight = clamp(idealRowHeight, 27, 44);
    const visibleRows = itemCount > 0
      ? Math.max(1, Math.floor(availableRowsHeight / rowHeight))
      : 0;
    const rankingOverflow = itemCount > visibleRows && itemCount > 0;
    const visualization = String(options.visualization || '').toLowerCase();
    const combined = Boolean(options.combined);
    const horizontalRanking = ['horizontal_bar', 'bar_gauge'].includes(
      visualization
    );
    const verticalRanking = ['bar', 'vertical_bar'].includes(visualization);
    const chartRowHeight = clamp(30 * scale, 25, 36);
    return Object.freeze({
      width: safeWidth,
      height: safeHeight,
      scale,
      fontSize,
      labelSize,
      gap,
      rowHeight,
      visibleRows,
      itemCount,
      rankingOverflow,
      chartScroll: !combined && rankingOverflow
        ? horizontalRanking
          ? 'vertical'
          : verticalRanking
            ? 'horizontal'
            : 'none'
        : 'none',
      chartMinHeight: horizontalRanking && !combined
        ? Math.max(safeHeight, itemCount * chartRowHeight + 54)
        : safeHeight,
      chartMinWidth: verticalRanking && !combined
        ? Math.max(safeWidth, itemCount * clamp(54 * scale, 46, 64) + 70)
        : safeWidth
    });
  }

  function applyWidgetResponsiveLayout(element, width, options = {}) {
    const layout = getWidgetResponsiveLayout(width, options);
    if (!element) return layout;
    const metrics = getWidgetContentMetrics(
      width,
      options.height ?? element.getBoundingClientRect?.().height,
      options
    );
    element.dataset.responsiveLayout = layout.mode;
    element.dataset.responsiveTableDensity = layout.tableDensity;
    element.dataset.responsiveOverflow = metrics.rankingOverflow ? 'scroll' : 'fit';
    element.dataset.chartScroll = metrics.chartScroll;
    element.style?.setProperty('--ranking-chart-ratio', `${layout.chartRatio}%`);
    element.style?.setProperty('--widget-scale', metrics.scale.toFixed(3));
    element.style?.setProperty('--widget-font-size', `${metrics.fontSize.toFixed(2)}px`);
    element.style?.setProperty('--widget-label-size', `${metrics.labelSize.toFixed(2)}px`);
    element.style?.setProperty('--widget-gap', `${metrics.gap.toFixed(2)}px`);
    element.style?.setProperty('--widget-row-height', `${metrics.rowHeight.toFixed(2)}px`);
    element.style?.setProperty('--widget-chart-min-height', `${Math.ceil(metrics.chartMinHeight)}px`);
    element.style?.setProperty('--widget-chart-min-width', `${Math.ceil(metrics.chartMinWidth)}px`);
    element.style?.setProperty('--widget-visible-rows', String(metrics.visibleRows));
    element.style?.setProperty(
      '--widget-stacked-breakpoint',
      `${layout.breakpoints.stacked}px`
    );
    element.style?.setProperty(
      '--widget-wide-breakpoint',
      `${layout.breakpoints.wide}px`
    );
    return Object.freeze({ ...layout, metrics });
  }

  function getResponsiveLegendLayout(
    width,
    height,
    preferredPosition = 'top',
    options = {}
  ) {
    const layout = getWidgetResponsiveLayout(width, options);
    const safeHeight = Math.max(0, finiteNumber(height, 0));
    const compact = layout.mode !== 'wide' || safeHeight < 280;
    const normalizedPreference = ['top', 'bottom', 'right'].includes(preferredPosition)
      ? preferredPosition
      : 'top';
    const position = normalizedPreference === 'right'
      && layout.mode === 'wide'
      && safeHeight >= 280
      ? 'right'
      : layout.mode === 'wide' && safeHeight >= 220
        ? 'top'
        : 'bottom';
    return Object.freeze({
      position,
      preferredPosition: normalizedPreference,
      orient: position === 'right' ? 'vertical' : 'horizontal',
      type: 'scroll',
      compact,
      fontSize: compact ? 10 : 12,
      itemWidth: compact ? 10 : 14,
      itemHeight: compact ? 7 : 10,
      nameLimit: layout.mode === 'wide' ? 32 : layout.mode === 'medium' ? 22 : 14,
      maxRows: 1,
      height: position === 'right' ? Math.max(80, safeHeight - 24) : compact ? 22 : 26,
      width: position === 'right' ? Math.min(190, Math.max(120, layout.width * 0.24)) : null,
      top: ['top', 'right'].includes(position) ? 0 : null,
      bottom: position === 'bottom' ? 0 : null,
      left: position === 'right' ? null : 8,
      right: 8,
      pageIconSize: compact ? 10 : 12
    });
  }

  function getResponsivePieGeometry(width, height, options = {}) {
    const legend = options.legend || getResponsiveLegendLayout(
      width,
      height,
      options.preferredLegendPosition,
      options
    );
    const safeWidth = Math.max(0, finiteNumber(width, 0));
    const safeHeight = Math.max(0, finiteNumber(height, 0));
    const layout = getWidgetResponsiveLayout(safeWidth, options);
    let outerRadius = layout.mode === 'wide' ? 68 : layout.mode === 'medium' ? 62 : 56;
    if (safeHeight < 260) outerRadius -= 6;
    if (safeHeight < 190 || safeWidth < 240) outerRadius -= 6;
    outerRadius = clamp(outerRadius, 38, 68);
    const innerRadius = options.donut === false
      ? 0
      : Math.round(outerRadius * 0.58);
    return Object.freeze({
      radius: options.donut === false
        ? `${outerRadius}%`
        : [`${innerRadius}%`, `${outerRadius}%`],
      center: [
        legend.position === 'right' ? '42%' : '50%',
        legend.position === 'top' ? '56%' : legend.position === 'bottom' ? '44%' : '50%'
      ],
      outerRadius,
      innerRadius,
      labelWidth: Math.max(52, Math.floor(safeWidth * (layout.mode === 'wide' ? 0.22 : 0.3))),
      labelFontSize: layout.mode === 'wide' ? 12 : layout.mode === 'medium' ? 11 : 10,
      showOutsideLabels: layout.mode === 'wide' && safeHeight >= 280
    });
  }

  function debounce(callback, wait = 60) {
    let timer = null;
    const delay = Math.max(0, finiteNumber(wait, 60));
    const debounced = function debouncedCallback(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => {
        timer = null;
        callback.apply(this, args);
      }, delay);
    };
    debounced.cancel = () => {
      clearTimeout(timer);
      timer = null;
    };
    return debounced;
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
    DEFAULT_WIDGET_BREAKPOINTS,
    DIRECTION_ORDER,
    DISTINCT_SERIES_PALETTE,
    normalizeAppearance,
    stableSeriesHash,
    seriesIdentity,
    assignSeriesColors,
    seriesContrastRatio,
    sortTooltipRows,
    positionFloatingTooltip,
    externalTooltipOptions,
    canonicalMetric,
    consolidateDirectionSeries,
    getChartDensityMode,
    densitySettings,
    normalizeWidgetBreakpoints,
    getWidgetResponsiveLayout,
    getWidgetContentMetrics,
    applyWidgetResponsiveLayout,
    getResponsiveLegendLayout,
    getResponsivePieGeometry,
    debounce,
    truncateCategory,
    replaceChartOption
  });
});
