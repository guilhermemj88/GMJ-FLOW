(function dashboardResizeFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardResize = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardResize() {
  'use strict';

  const DEFAULT_COLUMNS = 12;
  const DEFAULT_ROW_HEIGHT = 48;
  const DEFAULT_GAP = 12;

  function integer(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.trunc(number) : Number(fallback);
  }

  function clamp(value, minimum, maximum) {
    return Math.max(minimum, Math.min(maximum, value));
  }

  function gridColumnsToPixelWidth(columns, columnWidth, gap = DEFAULT_GAP) {
    const count = Math.max(1, integer(columns, 1));
    return count * Math.max(0, Number(columnWidth) || 0) + (count - 1) * Math.max(0, Number(gap) || 0);
  }

  function gridRowsToPixelHeight(rows, rowHeight = DEFAULT_ROW_HEIGHT, gap = DEFAULT_GAP) {
    const count = Math.max(1, integer(rows, 1));
    return count * Math.max(1, Number(rowHeight) || DEFAULT_ROW_HEIGHT)
      + (count - 1) * Math.max(0, Number(gap) || 0);
  }

  function pixelWidthToGridColumns(
    pixelWidth,
    columnWidth,
    gap = DEFAULT_GAP,
    options = {}
  ) {
    const pitch = Math.max(1, Number(columnWidth) || 1) + Math.max(0, Number(gap) || 0);
    const columns = Math.round((Math.max(0, Number(pixelWidth) || 0) + Math.max(0, Number(gap) || 0)) / pitch);
    return clamp(
      columns,
      Math.max(1, integer(options.minColumns, 1)),
      Math.max(1, integer(options.maxColumns, DEFAULT_COLUMNS))
    );
  }

  function pixelHeightToGridRows(
    pixelHeight,
    rowHeight = DEFAULT_ROW_HEIGHT,
    gap = DEFAULT_GAP,
    options = {}
  ) {
    const pitch = Math.max(1, Number(rowHeight) || DEFAULT_ROW_HEIGHT)
      + Math.max(0, Number(gap) || 0);
    const rows = Math.round((Math.max(0, Number(pixelHeight) || 0) + Math.max(0, Number(gap) || 0)) / pitch);
    return clamp(
      rows,
      Math.max(1, integer(options.minRows, 1)),
      Math.max(1, integer(options.maxRows, 1000))
    );
  }

  function snapWidgetSize(item, requestedSize = {}, constraints = {}) {
    const source = item || {};
    const columns = Math.max(1, integer(constraints.columns, DEFAULT_COLUMNS));
    const x = clamp(integer(source.x, 0), 0, columns - 1);
    const minW = Math.max(1, integer(source.min_w ?? constraints.min_w, 1));
    const maxW = Math.max(
      minW,
      Math.min(columns - x, integer(source.max_w ?? constraints.max_w, columns))
    );
    const minH = Math.max(1, integer(source.min_h ?? constraints.min_h, 1));
    const maxH = Math.max(minH, integer(source.max_h ?? constraints.max_h, 1000));
    const lockWidth = Boolean(constraints.lockWidth);
    return {
      w: lockWidth
        ? clamp(integer(source.w, minW), minW, maxW)
        : clamp(integer(requestedSize.w, source.w || minW), minW, maxW),
      h: clamp(integer(requestedSize.h, source.h || minH), minH, maxH)
    };
  }

  function pointerDeltaToGridSize(session, clientX, clientY) {
    const direction = session.direction || 'se';
    const columnPitch = Math.max(1, session.columnWidth + session.columnGap);
    const rowPitch = Math.max(1, session.rowHeight + session.rowGap);
    const deltaColumns = Math.round((Number(clientX) - session.startX) / columnPitch)
      * session.columnFactor;
    const deltaRows = Math.round((Number(clientY) - session.startY) / rowPitch);
    return snapWidgetSize(
      session.item,
      {
        w: session.initialW + (direction.includes('e') ? deltaColumns : 0),
        h: session.initialH + (direction.includes('s') ? deltaRows : 0)
      },
      {
        ...session.constraints,
        lockWidth: session.lockWidth || !direction.includes('e')
      }
    );
  }

  function createDashboardResizeController(options) {
    if (!options?.grid) throw new Error('A grade do dashboard é obrigatória.');
    if (!options?.layoutEngine?.resizeItemAndPush) {
      throw new Error('O motor de auto-layout é obrigatório.');
    }
    const grid = options.grid;
    const layoutEngine = options.layoutEngine;
    const eventRoot = options.eventRoot || grid.ownerDocument;
    let session = null;
    let destroyed = false;

    function widgetElement(target) {
      return target?.closest?.(options.widgetSelector || '.configurable-dashboard-widget');
    }

    function resizeHandle(target) {
      return target?.closest?.(options.handleSelector || '[data-resize-handle]');
    }

    function sessionGeometry() {
      const style = typeof getComputedStyle === 'function' ? getComputedStyle(grid) : null;
      const gap = Number.parseFloat(style?.columnGap) || DEFAULT_GAP;
      const responsiveColumns = clamp(
        integer(options.getResponsiveColumns?.(), DEFAULT_COLUMNS),
        1,
        DEFAULT_COLUMNS
      );
      const width = Math.max(1, Number(grid.getBoundingClientRect?.().width) || 1);
      return {
        responsiveColumns,
        columnFactor: DEFAULT_COLUMNS / responsiveColumns,
        columnGap: gap,
        columnWidth: Math.max(1, (width - gap * (responsiveColumns - 1)) / responsiveColumns),
        rowGap: Number.parseFloat(style?.rowGap) || DEFAULT_GAP,
        rowHeight: Number(options.rowHeight || DEFAULT_ROW_HEIGHT)
      };
    }

    function begin(event, handle, element, widget, keyboard = false) {
      if (destroyed || session || !widget || options.canResize?.(widget, element) === false) return false;
      const item = options.getLayout().find(current => Number(current.id) === Number(widget.id));
      if (!item) return false;
      const geometry = sessionGeometry();
      const direction = handle.dataset.resizeHandle || 'se';
      session = {
        pointerId: keyboard ? null : event.pointerId,
        keyboard,
        handle,
        element,
        widget,
        item: { ...item },
        direction,
        startX: Number(event.clientX || 0),
        startY: Number(event.clientY || 0),
        initialW: Number(item.w),
        initialH: Number(item.h),
        keyboardDeltaW: 0,
        keyboardDeltaH: 0,
        originalLayout: options.getLayout().map(current => ({ ...current })),
        previewLayout: options.getLayout().map(current => ({ ...current })),
        constraints: options.getConstraints?.(widget) || {},
        lockWidth: geometry.responsiveColumns === 1,
        ...geometry,
        persisting: false
      };
      element.classList.add('is-resizing');
      grid.classList.add('has-widget-resizing');
      eventRoot.body?.classList.add('dashboard-widget-resizing');
      if (!keyboard) {
        event.preventDefault();
        event.stopPropagation();
        try {
          handle.setPointerCapture?.(event.pointerId);
        } catch {
          // Synthetic events and older browsers can reject pointer capture.
        }
      }
      options.onStart?.(session);
      return true;
    }

    function preview(size) {
      if (!session) return;
      const next = snapWidgetSize(session.item, size, {
        ...session.constraints,
        lockWidth: session.lockWidth
      });
      const layout = layoutEngine.resizeItemAndPush(
        session.originalLayout,
        session.widget.id,
        next.w,
        next.h
      );
      session.previewLayout = layout;
      session.previewSize = next;
      const badge = session.element.querySelector?.('.widget-resize-badge');
      if (badge) badge.textContent = `${next.w} col × ${next.h} linhas`;
      options.onPreview?.({
        widget: session.widget,
        layout,
        size: next,
        session
      });
    }

    function cleanup() {
      if (!session) return;
      const current = session;
      current.element.classList.remove('is-resizing');
      grid.classList.remove('has-widget-resizing');
      eventRoot.body?.classList.remove('dashboard-widget-resizing');
      try {
        if (
          current.pointerId !== null
          && current.handle.hasPointerCapture?.(current.pointerId)
        ) {
          current.handle.releasePointerCapture(current.pointerId);
        }
      } catch {
        // The browser may have released capture after pointercancel.
      }
      session = null;
      options.onFinish?.(current);
    }

    async function commit(event) {
      if (!session || session.persisting) return;
      const current = session;
      current.persisting = true;
      event?.preventDefault?.();
      const finalLayout = layoutEngine.repairDashboardLayout(
        current.previewLayout,
        current.widget.id
      );
      options.onPreview?.({
        widget: current.widget,
        layout: finalLayout,
        size: current.previewSize || { w: current.initialW, h: current.initialH },
        session: current,
        final: true
      });
      try {
        await options.onPersist?.({
          widget: current.widget,
          layout: finalLayout,
          size: current.previewSize || { w: current.initialW, h: current.initialH },
          session: current
        });
        cleanup();
      } catch (error) {
        await options.onRollback?.({
          widget: current.widget,
          layout: current.originalLayout,
          session: current,
          error
        });
        options.onError?.(error, current);
        cleanup();
      }
    }

    async function cancel(event) {
      if (!session || session.persisting) return;
      const current = session;
      event?.preventDefault?.();
      await options.onRollback?.({
        widget: current.widget,
        layout: current.originalLayout,
        session: current,
        cancelled: true
      });
      cleanup();
    }

    function onPointerDown(event) {
      if (event.button !== undefined && event.button !== 0) return;
      const handle = resizeHandle(event.target);
      const element = widgetElement(handle);
      const widget = options.getWidget?.(Number(element?.dataset.widgetId));
      begin(event, handle, element, widget, false);
    }

    function onPointerMove(event) {
      if (!session || session.keyboard || event.pointerId !== session.pointerId) return;
      event.preventDefault();
      preview(pointerDeltaToGridSize(session, event.clientX, event.clientY));
    }

    function onPointerUp(event) {
      if (!session || session.keyboard || event.pointerId !== session.pointerId) return;
      commit(event);
    }

    function onPointerCancel(event) {
      if (!session || session.keyboard || event.pointerId !== session.pointerId) return;
      cancel(event);
    }

    function onKeyDown(event) {
      const handle = resizeHandle(event.target);
      if (!handle && !session?.keyboard) return;
      if (event.key === 'Escape') {
        cancel(event);
        return;
      }
      if (event.key === 'Enter' && session?.keyboard) {
        commit(event);
        return;
      }
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].includes(event.key)) return;
      const element = widgetElement(handle);
      const widget = options.getWidget?.(Number(element?.dataset.widgetId));
      if (!session && !begin(event, handle, element, widget, true)) return;
      if (!session?.keyboard || session.handle !== handle) return;
      event.preventDefault();
      const step = event.shiftKey ? 2 : 1;
      if (session.direction.includes('e')) {
        if (event.key === 'ArrowRight') session.keyboardDeltaW += step;
        if (event.key === 'ArrowLeft') session.keyboardDeltaW -= step;
      }
      if (session.direction.includes('s')) {
        if (event.key === 'ArrowDown') session.keyboardDeltaH += step;
        if (event.key === 'ArrowUp') session.keyboardDeltaH -= step;
      }
      preview({
        w: session.initialW + session.keyboardDeltaW,
        h: session.initialH + session.keyboardDeltaH
      });
    }

    grid.addEventListener('pointerdown', onPointerDown);
    grid.addEventListener('pointermove', onPointerMove);
    grid.addEventListener('pointerup', onPointerUp);
    grid.addEventListener('pointercancel', onPointerCancel);
    grid.addEventListener('keydown', onKeyDown);

    return Object.freeze({
      get activeSession() {
        return session;
      },
      cancel,
      destroy() {
        if (destroyed) return;
        destroyed = true;
        if (session) cancel();
        grid.removeEventListener('pointerdown', onPointerDown);
        grid.removeEventListener('pointermove', onPointerMove);
        grid.removeEventListener('pointerup', onPointerUp);
        grid.removeEventListener('pointercancel', onPointerCancel);
        grid.removeEventListener('keydown', onKeyDown);
      }
    });
  }

  return Object.freeze({
    DEFAULT_COLUMNS,
    DEFAULT_ROW_HEIGHT,
    DEFAULT_GAP,
    pixelWidthToGridColumns,
    pixelHeightToGridRows,
    gridColumnsToPixelWidth,
    gridRowsToPixelHeight,
    snapWidgetSize,
    pointerDeltaToGridSize,
    createDashboardResizeController
  });
});
