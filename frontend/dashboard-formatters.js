(function dashboardFormattersFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardFormatters = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardFormatters() {
  'use strict';

  const LOCALE = 'pt-BR';
  const METRIC_ALIASES = Object.freeze({
    bps: 'bps',
    bits_s: 'bps',
    bits_per_second: 'bps',
    bit_s: 'bps',
    throughput_bps: 'bps',
    pps: 'pps',
    packets_s: 'pps',
    packets_per_second: 'pps',
    fps: 'fps',
    flows_s: 'fps',
    flows_per_second: 'fps',
    bytes: 'bytes',
    byte_count: 'bytes',
    total_bytes: 'bytes',
    estimated_bytes: 'bytes',
    percentage: 'percentage',
    percent: 'percentage',
    ratio: 'percentage',
    latency: 'latency',
    latency_ms: 'latency',
    delay_ms: 'latency',
    duration: 'duration',
    duration_s: 'duration',
    flows: 'count',
    flow_count: 'count',
    events: 'count',
    event_count: 'count',
    sessions: 'count',
    session_count: 'count',
    anomalies: 'count',
    anomaly_count: 'count',
    packets: 'count',
    count: 'count'
  });

  const DECIMAL_SCALES = Object.freeze({
    bps: Object.freeze([
      Object.freeze({ threshold: 1e12, divisor: 1e12, unit: 'Tbps' }),
      Object.freeze({ threshold: 1e9, divisor: 1e9, unit: 'Gbps' }),
      Object.freeze({ threshold: 1e6, divisor: 1e6, unit: 'Mbps' }),
      Object.freeze({ threshold: 1e3, divisor: 1e3, unit: 'Kbps' }),
      Object.freeze({ threshold: 0, divisor: 1, unit: 'bps' })
    ]),
    pps: Object.freeze([
      Object.freeze({ threshold: 1e9, divisor: 1e9, unit: 'Gpps' }),
      Object.freeze({ threshold: 1e6, divisor: 1e6, unit: 'Mpps' }),
      Object.freeze({ threshold: 1e3, divisor: 1e3, unit: 'Kpps' }),
      Object.freeze({ threshold: 0, divisor: 1, unit: 'pps' })
    ]),
    fps: Object.freeze([
      Object.freeze({ threshold: 1e9, divisor: 1e9, unit: 'Gflows/s' }),
      Object.freeze({ threshold: 1e6, divisor: 1e6, unit: 'Mflows/s' }),
      Object.freeze({ threshold: 1e3, divisor: 1e3, unit: 'Kflows/s' }),
      Object.freeze({ threshold: 0, divisor: 1, unit: 'flows/s' })
    ]),
    count: Object.freeze([
      Object.freeze({ threshold: 1e9, divisor: 1e9, unit: 'B' }),
      Object.freeze({ threshold: 1e6, divisor: 1e6, unit: 'M' }),
      Object.freeze({ threshold: 1e3, divisor: 1e3, unit: 'K' }),
      Object.freeze({ threshold: 0, divisor: 1, unit: '' })
    ])
  });

  function finiteNumber(value) {
    if (value === null || value === undefined || value === '') return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function normalizeMetric(metric) {
    const key = String(metric || 'count').trim().toLowerCase();
    return METRIC_ALIASES[key] || key || 'count';
  }

  function invalidValue(options = {}) {
    return options.invalidValue === undefined ? '-' : String(options.invalidValue);
  }

  function formatNumberValue(value, options = {}) {
    const number = finiteNumber(value);
    if (number === null) return invalidValue(options);
    return new Intl.NumberFormat(options.locale || LOCALE, {
      minimumFractionDigits: Math.max(0, Number(options.minimumFractionDigits || 0)),
      maximumFractionDigits: Math.max(
        0,
        Number(options.maximumFractionDigits ?? 2)
      ),
      useGrouping: options.useGrouping !== false
    }).format(number);
  }

  function scaleForValue(value, scales) {
    const magnitude = Math.abs(finiteNumber(value) || 0);
    return scales.find(scale => magnitude >= scale.threshold) || scales[scales.length - 1];
  }

  function selectMetricScale(maxValue, metric) {
    const normalizedMetric = normalizeMetric(metric);
    if (DECIMAL_SCALES[normalizedMetric]) {
      return {
        ...scaleForValue(maxValue, DECIMAL_SCALES[normalizedMetric]),
        metric: normalizedMetric,
        value_kind: normalizedMetric === 'count' ? 'count' : 'rate'
      };
    }
    if (normalizedMetric === 'bytes') {
      const magnitude = Math.abs(finiteNumber(maxValue) || 0);
      const scales = [
        { threshold: 1024 ** 4, divisor: 1024 ** 4, unit: 'TB' },
        { threshold: 1024 ** 3, divisor: 1024 ** 3, unit: 'GB' },
        { threshold: 1024 ** 2, divisor: 1024 ** 2, unit: 'MB' },
        { threshold: 1024, divisor: 1024, unit: 'KB' },
        { threshold: 0, divisor: 1, unit: 'B' }
      ];
      return { ...scaleForValue(magnitude, scales), metric: 'bytes', value_kind: 'bytes' };
    }
    if (normalizedMetric === 'percentage') {
      return { divisor: 1, unit: '%', metric: normalizedMetric, value_kind: 'percentage' };
    }
    if (normalizedMetric === 'latency') {
      const magnitude = Math.abs(finiteNumber(maxValue) || 0);
      if (magnitude >= 1000) {
        return { divisor: 1000, unit: 's', metric: normalizedMetric, value_kind: 'latency' };
      }
      if (magnitude > 0 && magnitude < 1) {
        return { divisor: .001, unit: 'µs', metric: normalizedMetric, value_kind: 'latency' };
      }
      return { divisor: 1, unit: 'ms', metric: normalizedMetric, value_kind: 'latency' };
    }
    if (normalizedMetric === 'duration') {
      const magnitude = Math.abs(finiteNumber(maxValue) || 0);
      if (magnitude >= 3600) {
        return { divisor: 3600, unit: 'h', metric: normalizedMetric, value_kind: 'duration' };
      }
      if (magnitude >= 60) {
        return { divisor: 60, unit: 'min', metric: normalizedMetric, value_kind: 'duration' };
      }
      if (magnitude > 0 && magnitude < 1) {
        return { divisor: .001, unit: 'ms', metric: normalizedMetric, value_kind: 'duration' };
      }
      return { divisor: 1, unit: 's', metric: normalizedMetric, value_kind: 'duration' };
    }
    return { ...scaleForValue(maxValue, DECIMAL_SCALES.count), metric: 'count', value_kind: 'count' };
  }

  function formatWithScale(value, scale, options = {}) {
    const number = finiteNumber(value);
    if (number === null) return invalidValue(options);
    const selected = scale || { divisor: 1, unit: '' };
    const formatted = formatNumberValue(number / Number(selected.divisor || 1), options);
    const showUnit = options.showUnit !== false;
    return showUnit && selected.unit ? `${formatted} ${selected.unit}` : formatted;
  }

  function formatBitsPerSecond(value, options = {}) {
    return formatWithScale(
      value,
      options.scale || selectMetricScale(value, 'bps'),
      options
    );
  }

  function formatPacketsPerSecond(value, options = {}) {
    return formatWithScale(
      value,
      options.scale || selectMetricScale(value, 'pps'),
      options
    );
  }

  function formatBytes(value, options = {}) {
    return formatWithScale(
      value,
      options.scale || selectMetricScale(value, 'bytes'),
      options
    );
  }

  function formatCount(value, options = {}) {
    const scale = options.compact === false
      ? { divisor: 1, unit: '' }
      : options.scale || selectMetricScale(value, 'count');
    return formatWithScale(value, scale, {
      ...options,
      maximumFractionDigits: options.maximumFractionDigits
        ?? (Number(scale.divisor || 1) === 1 ? 0 : 2)
    });
  }

  function formatPercentage(value, options = {}) {
    const number = finiteNumber(value);
    if (number === null) return invalidValue(options);
    const normalized = options.inputIsRatio ? number * 100 : number;
    return `${formatNumberValue(normalized, options)}%`;
  }

  function formatLatency(value, options = {}) {
    return formatWithScale(
      value,
      options.scale || selectMetricScale(value, 'latency'),
      options
    );
  }

  function formatDuration(value, options = {}) {
    return formatWithScale(
      value,
      options.scale || selectMetricScale(value, 'duration'),
      options
    );
  }

  function formatMetricValue(value, metric, options = {}) {
    switch (normalizeMetric(metric)) {
      case 'bps': return formatBitsPerSecond(value, options);
      case 'pps': return formatPacketsPerSecond(value, options);
      case 'fps':
        return formatWithScale(
          value,
          options.scale || selectMetricScale(value, 'fps'),
          options
        );
      case 'bytes': return formatBytes(value, options);
      case 'percentage': return formatPercentage(value, options);
      case 'latency': return formatLatency(value, options);
      case 'duration': return formatDuration(value, options);
      default: return formatCount(value, options);
    }
  }

  function formatAxisValue(value, metric, scale) {
    return formatMetricValue(value, metric, {
      scale: scale || selectMetricScale(value, metric),
      maximumFractionDigits: 2
    });
  }

  function formatTooltipValue(value, metric, scale) {
    return formatMetricValue(value, metric, {
      scale: scale || selectMetricScale(value, metric),
      maximumFractionDigits: 2
    });
  }

  function formatTableValue(value, metric, options = {}) {
    return formatMetricValue(value, metric, {
      maximumFractionDigits: 2,
      ...options
    });
  }

  return Object.freeze({
    LOCALE,
    normalizeMetric,
    formatBitsPerSecond,
    formatPacketsPerSecond,
    formatBytes,
    formatCount,
    formatPercentage,
    formatLatency,
    formatDuration,
    formatMetricValue,
    formatAxisValue,
    formatTooltipValue,
    formatTableValue,
    selectMetricScale
  });
});
