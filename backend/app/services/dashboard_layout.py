from __future__ import annotations

import copy
from typing import Any


GRID_COLUMNS = 12
DEFAULT_MAX_HEIGHT = 1000
MAX_LAYOUT_ITERATIONS = 10000


def _integer(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _id_sort_key(value: Any) -> tuple[int, str]:
    try:
        return 0, "%020d" % int(value)
    except (TypeError, ValueError):
        return 1, str(value)


def normalize_grid_item(
    item: dict[str, Any],
    constraints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source = copy.deepcopy(item if isinstance(item, dict) else {})
    rules = constraints if isinstance(constraints, dict) else {}
    columns = max(1, _integer(rules.get("columns"), GRID_COLUMNS))
    minimum_width = max(
        1,
        _integer(source.get("min_w", rules.get("min_w")), 1),
    )
    maximum_width = max(
        minimum_width,
        min(
            columns,
            _integer(source.get("max_w", rules.get("max_w")), columns),
        ),
    )
    minimum_height = max(
        1,
        _integer(source.get("min_h", rules.get("min_h")), 1),
    )
    maximum_height = max(
        minimum_height,
        _integer(
            source.get("max_h", rules.get("max_h")),
            DEFAULT_MAX_HEIGHT,
        ),
    )
    default_width = _integer(
        rules.get("default_w"),
        min(4, maximum_width),
    )
    default_height = _integer(rules.get("default_h"), 4)
    width = max(
        minimum_width,
        min(maximum_width, _integer(source.get("w"), default_width)),
    )
    height = max(
        minimum_height,
        min(maximum_height, _integer(source.get("h"), default_height)),
    )
    x = max(
        0,
        min(columns - width, _integer(source.get("x"), 0)),
    )
    y = max(0, _integer(source.get("y"), 0))
    source.update(
        {
            "x": x,
            "y": y,
            "w": width,
            "h": height,
            "min_w": minimum_width,
            "min_h": minimum_height,
            "max_w": maximum_width,
            "max_h": maximum_height,
        }
    )
    return source


def rectangles_overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return bool(
        int(a["x"]) < int(b["x"]) + int(b["w"])
        and int(a["x"]) + int(a["w"]) > int(b["x"])
        and int(a["y"]) < int(b["y"]) + int(b["h"])
        and int(a["y"]) + int(a["h"]) > int(b["y"])
    )


def items_overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if a.get("id") == b.get("id"):
        return False
    if bool(a.get("hidden")) or bool(b.get("hidden")):
        return False
    return rectangles_overlap(a, b)


def sort_layout(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            int(item["y"]),
            int(item["x"]),
            _id_sort_key(item.get("id")),
        ),
    )


def find_collisions(
    item: dict[str, Any],
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sort_layout(
        [
            current
            for current in items
            if items_overlap(item, current)
        ]
    )


def _normalized_layout(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized = [normalize_grid_item(item) for item in items]
    identifiers = [str(item.get("id")) for item in normalized]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("layout contém IDs duplicados")
    return normalized


def push_item_down(
    items: list[dict[str, Any]],
    item_id: Any,
    minimum_y: int,
) -> list[dict[str, Any]]:
    result = _normalized_layout(items)
    for item in result:
        if item.get("id") == item_id:
            item["y"] = max(int(item["y"]), max(0, int(minimum_y)))
            return result
    raise ValueError("widget não encontrado no layout")


def compact_layout_vertically(
    items: list[dict[str, Any]],
    priority_item_id: Any | None = None,
) -> list[dict[str, Any]]:
    result = _normalized_layout(items)
    by_id = {item.get("id"): item for item in result}
    for ordered in sort_layout(result):
        item = by_id[ordered.get("id")]
        if item.get("id") == priority_item_id or bool(item.get("hidden")):
            continue
        while int(item["y"]) > 0:
            candidate = dict(item, y=int(item["y"]) - 1)
            if any(
                items_overlap(candidate, other)
                for other in result
                if other.get("id") != item.get("id")
            ):
                break
            item["y"] = int(item["y"]) - 1
    return sort_layout(result)


def _place_without_collisions(
    items: list[dict[str, Any]],
    priority_item_id: Any | None,
) -> list[dict[str, Any]]:
    result = _normalized_layout(items)
    visible = [item for item in result if not bool(item.get("hidden"))]
    priority = next(
        (item for item in visible if item.get("id") == priority_item_id),
        None,
    )
    ordered = sort_layout(
        [
            item
            for item in visible
            if priority is None or item.get("id") != priority.get("id")
        ]
    )
    if priority is not None:
        ordered.insert(0, priority)
    placed: list[dict[str, Any]] = []
    iterations = 0
    for item in ordered:
        while True:
            collisions = find_collisions(item, placed)
            if not collisions:
                break
            if item.get("id") == priority_item_id:
                raise ValueError("o item prioritário não pode ser deslocado")
            item["y"] = max(
                int(item["y"]),
                max(int(other["y"]) + int(other["h"]) for other in collisions),
            )
            iterations += 1
            if iterations > MAX_LAYOUT_ITERATIONS:
                raise ValueError("limite de resolução de layout excedido")
        placed.append(item)
    return result


def resolve_collisions(
    items: list[dict[str, Any]],
    priority_item_id: Any | None = None,
) -> list[dict[str, Any]]:
    result = _normalized_layout(items)
    priority = next(
        (
            item
            for item in result
            if item.get("id") == priority_item_id and not bool(item.get("hidden"))
        ),
        None,
    )
    if priority is not None:
        queue = [priority.get("id")]
        iterations = 0
        while queue:
            current_id = queue.pop(0)
            current = next(
                item for item in result if item.get("id") == current_id
            )
            for collision in find_collisions(current, result):
                if collision.get("id") == priority_item_id:
                    continue
                minimum_y = int(current["y"]) + int(current["h"])
                if int(collision["y"]) < minimum_y:
                    collision["y"] = minimum_y
                    queue.append(collision.get("id"))
                iterations += 1
                if iterations > MAX_LAYOUT_ITERATIONS:
                    raise ValueError("limite de push vertical excedido")
    result = _place_without_collisions(result, priority_item_id)
    result = compact_layout_vertically(result, priority_item_id)
    validation = validate_layout(result)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    return result


def move_item_and_push(
    items: list[dict[str, Any]],
    item_id: Any,
    target_x: int,
    target_y: int,
) -> list[dict[str, Any]]:
    result = _normalized_layout(items)
    target = next(
        (item for item in result if item.get("id") == item_id),
        None,
    )
    if target is None:
        raise ValueError("widget não encontrado no layout")
    target.update(
        normalize_grid_item(
            dict(target, x=target_x, y=target_y)
        )
    )
    return resolve_collisions(result, item_id)


def resize_item_and_push(
    items: list[dict[str, Any]],
    item_id: Any,
    target_w: int,
    target_h: int,
) -> list[dict[str, Any]]:
    result = _normalized_layout(items)
    target = next(
        (item for item in result if item.get("id") == item_id),
        None,
    )
    if target is None:
        raise ValueError("widget não encontrado no layout")
    target.update(
        normalize_grid_item(
            dict(target, w=target_w, h=target_h)
        )
    )
    return resolve_collisions(result, item_id)


def repair_dashboard_layout(
    items: list[dict[str, Any]],
    priority_item_id: Any | None = None,
) -> list[dict[str, Any]]:
    normalized = _normalized_layout(items)
    visible = [item for item in normalized if not bool(item.get("hidden"))]
    hidden = [item for item in normalized if bool(item.get("hidden"))]
    priority = next(
        (item for item in visible if item.get("id") == priority_item_id),
        None,
    )

    def horizontal_overlap(
        left: dict[str, Any],
        right: dict[str, Any],
    ) -> bool:
        return bool(
            int(left["x"]) < int(right["x"]) + int(right["w"])
            and int(left["x"]) + int(left["w"]) > int(right["x"])
        )

    groups: list[list[dict[str, Any]]] = []
    rows: dict[int, list[dict[str, Any]]] = {}
    for item in visible:
        if priority is not None and item.get("id") == priority.get("id"):
            continue
        rows.setdefault(int(item["y"]), []).append(item)
    for row_y in sorted(rows):
        row_groups: list[list[dict[str, Any]]] = []
        for item in sorted(
            rows[row_y],
            key=lambda current: (
                int(current["x"]),
                _id_sort_key(current.get("id")),
            ),
        ):
            target = next(
                (
                    group
                    for group in row_groups
                    if not any(
                        horizontal_overlap(item, member)
                        for member in group
                    )
                ),
                None,
            )
            if target is None:
                row_groups.append([item])
            else:
                target.append(item)
        groups.extend(row_groups)
    groups.sort(
        key=lambda group: (
            min(int(item["y"]) for item in group),
            min(int(item["x"]) for item in group),
            min(_id_sort_key(item.get("id")) for item in group),
        )
    )
    if priority is not None:
        groups.insert(0, [priority])

    placed: list[dict[str, Any]] = []
    iterations = 0
    for group in groups:
        while True:
            required_shift = 0
            for item in group:
                for other in placed:
                    if not horizontal_overlap(item, other):
                        continue
                    if (
                        int(item["y"]) < int(other["y"]) + int(other["h"])
                        and int(item["y"]) + int(item["h"]) > int(other["y"])
                    ):
                        required_shift = max(
                            required_shift,
                            int(other["y"])
                            + int(other["h"])
                            - int(item["y"]),
                        )
            if required_shift <= 0:
                break
            for item in group:
                item["y"] = int(item["y"]) + required_shift
            iterations += 1
            if iterations > MAX_LAYOUT_ITERATIONS:
                raise ValueError("limite de reparo do layout excedido")
        placed.extend(group)

    all_visible = [item for group in groups for item in group]
    compact_iterations = 0
    while True:
        moved = False
        for group in groups:
            if (
                priority is not None
                and group[0].get("id") == priority.get("id")
            ):
                continue
            group_moved = False
            while min(int(item["y"]) for item in group) > 0:
                candidates = [
                    dict(item, y=int(item["y"]) - 1)
                    for item in group
                ]
                group_ids = {item.get("id") for item in group}
                if any(
                    rectangles_overlap(candidate, other)
                    for candidate in candidates
                    for other in all_visible
                    if other.get("id") not in group_ids
                ):
                    break
                for item in group:
                    item["y"] = int(item["y"]) - 1
                group_moved = True
            moved = moved or group_moved
        if not moved:
            break
        compact_iterations += 1
        if compact_iterations > MAX_LAYOUT_ITERATIONS:
            raise ValueError("limite de compactação do layout excedido")

    repaired = sort_layout(all_visible + hidden)
    validation = validate_layout(repaired)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    return repaired


def validate_layout(items: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    normalized = _normalized_layout(items)
    for item in normalized:
        if int(item["x"]) < 0 or int(item["y"]) < 0:
            errors.append("posição negativa no widget %s" % item.get("id"))
        if int(item["w"]) < 1 or int(item["h"]) < 1:
            errors.append("dimensão inválida no widget %s" % item.get("id"))
        if int(item["x"]) + int(item["w"]) > GRID_COLUMNS:
            errors.append("widget %s excede 12 colunas" % item.get("id"))
    visible = [item for item in normalized if not bool(item.get("hidden"))]
    for index, left in enumerate(visible):
        for right in visible[index + 1 :]:
            if items_overlap(left, right):
                errors.append(
                    "widgets %s e %s sobrepostos"
                    % (left.get("id"), right.get("id"))
                )
    return {"valid": not errors, "errors": errors}


def layout_signature(items: list[dict[str, Any]]) -> tuple[Any, ...]:
    return tuple(
        (
            item.get("id"),
            int(item["x"]),
            int(item["y"]),
            int(item["w"]),
            int(item["h"]),
            bool(item.get("hidden")),
        )
        for item in sort_layout(_normalized_layout(items))
    )
