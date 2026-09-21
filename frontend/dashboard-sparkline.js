(function dashboardSparklineFactory(root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.GMJDashboardSparkline = factory();
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardSparkline() {
  'use strict';

  function finite(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
  }

  function points(data) {
    return (Array.isArray(data) ? data : []).map(finite);
  }

  function renderSparkline(data, options = {}) {
    const values = points(data);
    if (values.length < 2) return '';
    const width = Number(options.width) || 72;
    const height = Number(options.height) || 18;
    const color = options.color || 'var(--accent, #7A67E8)';
    const fill = options.fill !== false;
    const strokeWidth = Number(options.strokeWidth) || 1;
    const className = options.className || '';
    const pad = strokeWidth + 0.5;
    const min = Math.min.apply(null, values);
    const max = Math.max.apply(null, values);
    const span = max - min || 1;
    const stepX = (width - pad * 2) / (values.length - 1);
    const coords = values.map((value, index) => {
      const x = pad + index * stepX;
      const y = pad + (1 - (value - min) / span) * (height - pad * 2);
      return [Number(x.toFixed(2)), Number(y.toFixed(2))];
    });
    const line = coords.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x},${y}`).join(' ');
    const area = `${line} L${coords[coords.length - 1][0]},${height} L${coords[0][0]},${height} Z`;
    const gradientId = 'spark-' + Math.random().toString(36).slice(2, 9);
    const fillMarkup = fill
      ? `<defs><linearGradient id="${gradientId}" x1="0" y1="0" x2="0" y2="1">` +
        `<stop offset="0%" stop-color="${color}" stop-opacity="0.22"></stop>` +
        `<stop offset="100%" stop-color="${color}" stop-opacity="0"></stop>` +
        `</linearGradient></defs>` +
        `<path d="${area}" fill="url(#${gradientId})"></path>`
      : '';
    return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" class="sparkline ${className}" aria-hidden="true" focusable="false">${fillMarkup}<path d="${line}" fill="none" stroke="${color}" stroke-width="${strokeWidth}" stroke-linejoin="round"></path></svg>`;
  }

  return {
    renderSparkline: renderSparkline
  };
});
