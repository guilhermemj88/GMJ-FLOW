(function dashboardPrefixControlsFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardPrefixControls = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardPrefixControls() {
  'use strict';

  const STORAGE_PREFIX = 'gmjflow.dashboard-prefix-controls.collapsed.v1';

  function storageKey(dashboardId) {
    const identifier = Number(dashboardId) || 'global';
    return `${STORAGE_PREFIX}:${identifier}`;
  }

  function readCollapsed(storage, dashboardId, fallback = true) {
    try {
      const saved = storage?.getItem?.(storageKey(dashboardId));
      if (saved === null || saved === undefined || saved === '') return Boolean(fallback);
      return saved !== 'false';
    } catch {
      return Boolean(fallback);
    }
  }

  function writeCollapsed(storage, dashboardId, collapsed) {
    try {
      storage?.setItem?.(storageKey(dashboardId), String(Boolean(collapsed)));
    } catch {
      // Browsers can disable storage; the current in-memory state still works.
    }
  }

  function prefixSummaryState(filter = {}, grouping = {}, options = {}) {
    const enabled = Boolean(filter?.enabled);
    const active = enabled
      ? filter.cidr
        || (filter.start_ip && filter.end_ip
          ? `${filter.start_ip}–${filter.end_ip}`
          : 'família selecionada')
      : 'Todos os IPs';
    const matchLabel = {
      source: 'origem',
      destination: 'destino',
      either: 'origem ou destino',
      both: 'origem e destino'
    }[filter?.match_side] || 'origem ou destino';
    const groupingLabel = `IPv4 /${grouping?.ipv4_prefix_length ?? 24} · IPv6 /${grouping?.ipv6_prefix_length ?? 64}`;
    const temporary = enabled && Boolean(options.temporary);
    const badge = !enabled
      ? 'Sem filtro'
      : temporary
        ? 'Filtro temporário'
        : 'Filtro salvo';
    const scope = options.scope === 'dashboard' ? 'dashboard atual' : 'global';
    const text = enabled
      ? `Filtro ativo: ${active} · Aplicação: ${matchLabel} · Agrupamento: ${groupingLabel}${temporary ? ` · Temporário ${scope}` : ''}`
      : `${active} · Agrupamento: ${groupingLabel}`;
    return Object.freeze({
      active,
      badge,
      badgeKind: !enabled ? 'none' : temporary ? 'temporary' : 'saved',
      hasFilter: enabled,
      text
    });
  }

  function createController(options = {}) {
    const panel = options.panel;
    const body = options.body;
    const header = options.header;
    const toggleButton = options.toggleButton;
    const collapseButton = options.collapseButton;
    const storage = options.storage;
    if (!panel || !body || !header || !toggleButton) {
      throw new Error('Painel, corpo, cabeçalho e botão de filtros são obrigatórios.');
    }
    let collapsed = true;
    let destroyed = false;

    function dashboardId() {
      return options.getDashboardId?.() || 'global';
    }

    function render() {
      panel.classList.toggle('is-collapsed', collapsed);
      body.hidden = collapsed;
      header.setAttribute('aria-expanded', String(!collapsed));
      toggleButton.setAttribute('aria-expanded', String(!collapsed));
      toggleButton.setAttribute(
        'aria-label',
        collapsed ? 'Expandir filtros de IPs e prefixos' : 'Recolher filtros de IPs e prefixos'
      );
      const label = toggleButton.querySelector?.('[data-prefix-toggle-label]');
      if (label) label.textContent = collapsed ? 'Expandir' : 'Recolher';
      options.onChange?.(collapsed);
    }

    function setCollapsed(value, settings = {}) {
      if (destroyed) return collapsed;
      collapsed = Boolean(value);
      if (settings.persist !== false) {
        writeCollapsed(storage, dashboardId(), collapsed);
      }
      render();
      return collapsed;
    }

    function toggle() {
      return setCollapsed(!collapsed);
    }

    function restore(targetDashboardId = dashboardId()) {
      collapsed = readCollapsed(storage, targetDashboardId, true);
      render();
      return collapsed;
    }

    function onHeaderClick(event) {
      if (event.target?.closest?.('button, a, input, select, textarea')) return;
      toggle();
    }

    function onHeaderKeyDown(event) {
      if (event.target !== header) return;
      if (!['Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      toggle();
    }

    function onToggleClick(event) {
      event.preventDefault();
      event.stopPropagation();
      toggle();
    }

    function onCollapseClick(event) {
      event.preventDefault();
      setCollapsed(true);
      header.focus?.();
    }

    header.addEventListener('click', onHeaderClick);
    header.addEventListener('keydown', onHeaderKeyDown);
    toggleButton.addEventListener('click', onToggleClick);
    collapseButton?.addEventListener('click', onCollapseClick);
    restore();

    return Object.freeze({
      get collapsed() {
        return collapsed;
      },
      setCollapsed,
      toggle,
      restore,
      expandForError() {
        return setCollapsed(false);
      },
      destroy() {
        if (destroyed) return;
        destroyed = true;
        header.removeEventListener('click', onHeaderClick);
        header.removeEventListener('keydown', onHeaderKeyDown);
        toggleButton.removeEventListener('click', onToggleClick);
        collapseButton?.removeEventListener('click', onCollapseClick);
      }
    });
  }

  return Object.freeze({
    STORAGE_PREFIX,
    storageKey,
    readCollapsed,
    writeCollapsed,
    prefixSummaryState,
    createController
  });
});
