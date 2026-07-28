(function dashboardLayoutFactory(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.GMJDashboardLayout = api;
})(typeof window !== 'undefined' ? window : globalThis, function createDashboardLayout() {
  'use strict';

  const GRID_COLUMNS = 12;
  const DEFAULT_MAX_HEIGHT = 1000;
  const MAX_LAYOUT_ITERATIONS = 10000;
  const DEFAULT_ROW_HEIGHT = 48;
  const DEFAULT_ROW_GAP = 12;

  function integer(value, fallback) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? Math.trunc(parsed) : Number(fallback);
  }

  function idSortKey(value) {
    const parsed = Number(value);
    return Number.isFinite(parsed)
      ? `0:${String(Math.trunc(parsed)).padStart(20, '0')}`
      : `1:${String(value)}`;
  }

  function normalizeGridItem(item, constraints = {}) {
    const source = { ...(item || {}) };
    const columns = Math.max(1, integer(constraints.columns, GRID_COLUMNS));
    const minW = Math.max(1, integer(source.min_w ?? constraints.min_w, 1));
    const maxW = Math.max(
      minW,
      Math.min(columns, integer(source.max_w ?? constraints.max_w, columns))
    );
    const minH = Math.max(1, integer(source.min_h ?? constraints.min_h, 1));
    const maxH = Math.max(
      minH,
      integer(source.max_h ?? constraints.max_h, DEFAULT_MAX_HEIGHT)
    );
    const defaultW = integer(constraints.default_w, Math.min(4, maxW));
    const defaultH = integer(constraints.default_h, 4);
    const w = Math.max(minW, Math.min(maxW, integer(source.w, defaultW)));
    const h = Math.max(minH, Math.min(maxH, integer(source.h, defaultH)));
    const x = Math.max(0, Math.min(columns - w, integer(source.x, 0)));
    const y = Math.max(0, integer(source.y, 0));
    return {
      ...source,
      x,
      y,
      w,
      h,
      min_w: minW,
      min_h: minH,
      max_w: maxW,
      max_h: maxH
    };
  }

  function rectanglesOverlap(a, b) {
    return (
      a.x < b.x + b.w
      && a.x + a.w > b.x
      && a.y < b.y + b.h
      && a.y + a.h > b.y
    );
  }

  function itemsOverlap(a, b) {
    if (a.id === b.id || a.hidden || b.hidden) return false;
    return rectanglesOverlap(a, b);
  }

  function sortLayout(items) {
    return [...items].sort((left, right) => {
      const position = left.y - right.y || left.x - right.x;
      if (position) return position;
      const leftId = idSortKey(left.id);
      const rightId = idSortKey(right.id);
      return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
    });
  }

  function findCollisions(item, items) {
    return sortLayout(items.filter(current => itemsOverlap(item, current)));
  }

  function normalizedLayout(items) {
    const normalized = (items || []).map(item => normalizeGridItem(item));
    const ids = normalized.map(item => String(item.id));
    if (new Set(ids).size !== ids.length) throw new Error('Layout contém IDs duplicados.');
    return normalized;
  }

  function pushItemDown(items, itemId, minimumY) {
    const result = normalizedLayout(items);
    const target = result.find(item => item.id === itemId);
    if (!target) throw new Error('Widget não encontrado no layout.');
    target.y = Math.max(target.y, Math.max(0, integer(minimumY, 0)));
    return result;
  }

  function compactLayoutVertically(items, priorityItemId = null) {
    const result = normalizedLayout(items);
    const byId = new Map(result.map(item => [item.id, item]));
    for (const ordered of sortLayout(result)) {
      const item = byId.get(ordered.id);
      if (item.id === priorityItemId || item.hidden) continue;
      while (item.y > 0) {
        const candidate = { ...item, y: item.y - 1 };
        if (result.some(other => other.id !== item.id && itemsOverlap(candidate, other))) break;
        item.y -= 1;
      }
    }
    return sortLayout(result);
  }

  function placeWithoutCollisions(items, priorityItemId = null) {
    const result = normalizedLayout(items);
    const visible = result.filter(item => !item.hidden);
    const priority = visible.find(item => item.id === priorityItemId);
    const ordered = sortLayout(
      visible.filter(item => !priority || item.id !== priority.id)
    );
    if (priority) ordered.unshift(priority);
    const placed = [];
    let iterations = 0;
    for (const item of ordered) {
      while (true) {
        const collisions = findCollisions(item, placed);
        if (!collisions.length) break;
        if (item.id === priorityItemId) {
          throw new Error('O item prioritário não pode ser deslocado.');
        }
        item.y = Math.max(item.y, ...collisions.map(other => other.y + other.h));
        iterations += 1;
        if (iterations > MAX_LAYOUT_ITERATIONS) {
          throw new Error('Limite de resolução de layout excedido.');
        }
      }
      placed.push(item);
    }
    return result;
  }

  function resolveCollisions(items, priorityItemId = null) {
    let result = normalizedLayout(items);
    const priority = result.find(item => item.id === priorityItemId && !item.hidden);
    if (priority) {
      const queue = [priority.id];
      let iterations = 0;
      while (queue.length) {
        const currentId = queue.shift();
        const current = result.find(item => item.id === currentId);
        for (const collision of findCollisions(current, result)) {
          if (collision.id === priorityItemId) continue;
          const minimumY = current.y + current.h;
          if (collision.y < minimumY) {
            collision.y = minimumY;
            queue.push(collision.id);
          }
          iterations += 1;
          if (iterations > MAX_LAYOUT_ITERATIONS) {
            throw new Error('Limite de push vertical excedido.');
          }
        }
      }
    }
    result = placeWithoutCollisions(result, priorityItemId);
    result = compactLayoutVertically(result, priorityItemId);
    const validation = validateLayout(result);
    if (!validation.valid) throw new Error(validation.errors.join('; '));
    return result;
  }

  function moveItemAndPush(items, itemId, targetX, targetY) {
    const result = normalizedLayout(items);
    const target = result.find(item => item.id === itemId);
    if (!target) throw new Error('Widget não encontrado no layout.');
    Object.assign(target, normalizeGridItem({ ...target, x: targetX, y: targetY }));
    return resolveCollisions(result, itemId);
  }

  function resizeItemAndPush(items, itemId, targetW, targetH) {
    const result = normalizedLayout(items);
    const target = result.find(item => item.id === itemId);
    if (!target) throw new Error('Widget não encontrado no layout.');
    Object.assign(target, normalizeGridItem({ ...target, w: targetW, h: targetH }));
    return resolveCollisions(result, itemId);
  }

  function resolveLayoutDuringInteraction(
    persistentLayout,
    itemId,
    geometry = {},
    options = {}
  ) {
    const interactionLayout = normalizedLayout(persistentLayout);
    const active = interactionLayout.find(item => item.id === itemId);
    if (!active) throw new Error('Widget não encontrado no layout.');
    Object.assign(active, normalizeGridItem({ ...active, ...geometry }));
    let resolved = resolveCollisions(interactionLayout, itemId);
    if (options.compact === false) {
      resolved = placeWithoutCollisions(interactionLayout, itemId);
    }
    const validation = validateLayout(resolved);
    if (!validation.valid) throw new Error(validation.errors.join('; '));
    return sortLayout(resolved);
  }

  function calculateResizePreview(
    persistentLayout,
    itemId,
    targetW,
    targetH,
    options = {}
  ) {
    return resolveLayoutDuringInteraction(
      persistentLayout,
      itemId,
      { w: targetW, h: targetH },
      options
    );
  }

  function calculateMovePreview(
    persistentLayout,
    itemId,
    targetX,
    targetY,
    options = {}
  ) {
    return resolveLayoutDuringInteraction(
      persistentLayout,
      itemId,
      { x: targetX, y: targetY },
      options
    );
  }

  function commitLayoutInteraction(interactionLayout) {
    const committed = sortLayout(normalizedLayout(interactionLayout));
    const validation = validateLayout(committed);
    if (!validation.valid) throw new Error(validation.errors.join('; '));
    return committed;
  }

  function rollbackLayoutInteraction(persistentLayout) {
    return sortLayout(normalizedLayout(persistentLayout));
  }

  function repairDashboardLayout(items, priorityItemId = null) {
    const normalized = normalizedLayout(items);
    const visible = normalized.filter(item => !item.hidden);
    const hidden = normalized.filter(item => item.hidden);
    const priority = visible.find(item => item.id === priorityItemId);
    const horizontalOverlap = (left, right) => (
      left.x < right.x + right.w && left.x + left.w > right.x
    );
    const rows = new Map();
    visible.forEach(item => {
      if (priority && item.id === priority.id) return;
      if (!rows.has(item.y)) rows.set(item.y, []);
      rows.get(item.y).push(item);
    });
    const groups = [];
    [...rows.keys()].sort((left, right) => left - right).forEach(rowY => {
      const rowGroups = [];
      rows.get(rowY)
        .sort((left, right) => left.x - right.x || (
          idSortKey(left.id) < idSortKey(right.id) ? -1 : 1
        ))
        .forEach(item => {
          const target = rowGroups.find(group => (
            !group.some(member => horizontalOverlap(item, member))
          ));
          if (target) target.push(item);
          else rowGroups.push([item]);
        });
      groups.push(...rowGroups);
    });
    groups.sort((left, right) => (
      Math.min(...left.map(item => item.y)) - Math.min(...right.map(item => item.y))
      || Math.min(...left.map(item => item.x)) - Math.min(...right.map(item => item.x))
      || (idSortKey(left[0].id) < idSortKey(right[0].id) ? -1 : 1)
    ));
    if (priority) groups.unshift([priority]);

    const placed = [];
    let iterations = 0;
    groups.forEach(group => {
      while (true) {
        let requiredShift = 0;
        group.forEach(item => {
          placed.forEach(other => {
            if (
              horizontalOverlap(item, other)
              && item.y < other.y + other.h
              && item.y + item.h > other.y
            ) {
              requiredShift = Math.max(requiredShift, other.y + other.h - item.y);
            }
          });
        });
        if (requiredShift <= 0) break;
        group.forEach(item => { item.y += requiredShift; });
        iterations += 1;
        if (iterations > MAX_LAYOUT_ITERATIONS) {
          throw new Error('Limite de reparo do layout excedido.');
        }
      }
      placed.push(...group);
    });

    const allVisible = groups.flat();
    let compactIterations = 0;
    while (true) {
      let moved = false;
      groups.forEach(group => {
        if (priority && group[0].id === priority.id) return;
        const groupIds = new Set(group.map(item => item.id));
        let groupMoved = false;
        while (Math.min(...group.map(item => item.y)) > 0) {
          const candidates = group.map(item => ({ ...item, y: item.y - 1 }));
          const collision = candidates.some(candidate => (
            allVisible.some(other => (
              !groupIds.has(other.id) && rectanglesOverlap(candidate, other)
            ))
          ));
          if (collision) break;
          group.forEach(item => { item.y -= 1; });
          groupMoved = true;
        }
        moved = moved || groupMoved;
      });
      if (!moved) break;
      compactIterations += 1;
      if (compactIterations > MAX_LAYOUT_ITERATIONS) {
        throw new Error('Limite de compactação do layout excedido.');
      }
    }
    const repaired = sortLayout(allVisible.concat(hidden));
    const validation = validateLayout(repaired);
    if (!validation.valid) {
      throw new Error(validation.errors.join('; '));
    }
    return repaired;
  }

  function validateLayout(items) {
    const errors = [];
    const normalized = normalizedLayout(items);
    for (const item of normalized) {
      if (item.x < 0 || item.y < 0) errors.push(`Posição negativa no widget ${item.id}.`);
      if (item.w < 1 || item.h < 1) errors.push(`Dimensão inválida no widget ${item.id}.`);
      if (item.x + item.w > GRID_COLUMNS) errors.push(`Widget ${item.id} excede 12 colunas.`);
    }
    const visible = normalized.filter(item => !item.hidden);
    visible.forEach((left, index) => {
      visible.slice(index + 1).forEach(right => {
        if (itemsOverlap(left, right)) {
          errors.push(`Widgets ${left.id} e ${right.id} sobrepostos.`);
        }
      });
    });
    return { valid: errors.length === 0, errors };
  }

  function calculateGridPixelHeight(
    heightUnits,
    rowHeight = DEFAULT_ROW_HEIGHT,
    rowGap = DEFAULT_ROW_GAP
  ) {
    const h = Math.max(1, integer(heightUnits, 1));
    return h * rowHeight + (h - 1) * rowGap;
  }

  function requiredGridHeight(
    contentHeight,
    rowHeight = DEFAULT_ROW_HEIGHT,
    rowGap = DEFAULT_ROW_GAP
  ) {
    return Math.max(
      1,
      Math.ceil((Math.max(0, Number(contentHeight) || 0) + rowGap) / (rowHeight + rowGap))
    );
  }

  function layoutSignature(items) {
    return JSON.stringify(
      sortLayout(normalizedLayout(items)).map(item => [
        item.id,
        item.x,
        item.y,
        item.w,
        item.h,
        Boolean(item.hidden)
      ])
    );
  }

  return Object.freeze({
    GRID_COLUMNS,
    DEFAULT_ROW_HEIGHT,
    DEFAULT_ROW_GAP,
    normalizeGridItem,
    rectanglesOverlap,
    itemsOverlap,
    findCollisions,
    moveItemAndPush,
    resizeItemAndPush,
    calculateResizePreview,
    calculateMovePreview,
    resolveLayoutDuringInteraction,
    commitLayoutInteraction,
    rollbackLayoutInteraction,
    pushItemDown,
    resolveCollisions,
    compactLayoutVertically,
    repairDashboardLayout,
    validateLayout,
    sortLayout,
    calculateGridPixelHeight,
    requiredGridHeight,
    layoutSignature
  });
});
