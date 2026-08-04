from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any


def _permission(
    code: str,
    name: str,
    description: str,
    category: str,
    risk: str,
) -> dict[str, str]:
    return {
        "code": code,
        "name": name,
        "description": description,
        "category": category,
        "risk": risk,
    }


PERMISSION_CATALOG: dict[str, dict[str, str]] = {
    item["code"]: item
    for item in (
        _permission("dashboard.view", "Visualizar dashboards", "Consultar dashboards e seus dados.", "Dashboard", "low"),
        _permission("dashboard.edit", "Editar dashboards", "Editar widgets e layouts próprios.", "Dashboard", "medium"),
        _permission("dashboard.manage", "Administrar dashboards", "Importar, compartilhar e administrar dashboards.", "Dashboard", "high"),
        _permission("anomalies.view", "Visualizar anomalias", "Consultar anomalias e histórico.", "Anomalias", "low"),
        _permission("anomalies.manage", "Gerenciar anomalias", "Reconhecer, encerrar e configurar detecção.", "Anomalias", "medium"),
        _permission("mitigations.view", "Visualizar mitigações", "Consultar avaliações e execuções de mitigação.", "Mitigações", "low"),
        _permission("mitigations.apply", "Aplicar mitigação", "Aplicar uma ação de mitigação.", "Mitigações", "critical"),
        _permission("mitigations.withdraw", "Retirar mitigação", "Retirar uma mitigação ativa.", "Mitigações", "critical"),
        _permission("mitigations.configure", "Configurar mitigações", "Alterar políticas e perfis de mitigação.", "Mitigações", "critical"),
        _permission("bgp.view", "Visualizar BGP", "Consultar conectores, perfis e anúncios BGP.", "BGP", "low"),
        _permission("bgp.manage", "Administrar BGP", "Configurar conectores, políticas e prefixos BGP.", "BGP", "critical"),
        _permission("bgp.apply", "Aplicar ações BGP", "Anunciar, aprovar, rejeitar ou retirar rotas.", "BGP", "critical"),
        _permission("sensors.view", "Visualizar sensores", "Consultar sensores e interfaces.", "Sensores", "low"),
        _permission("sensors.manage", "Administrar sensores", "Criar, editar, remover e calibrar sensores.", "Sensores", "high"),
        _permission("collectors.view", "Visualizar coletores", "Consultar configuração e saúde dos coletores.", "Coletores", "low"),
        _permission("collectors.manage", "Administrar coletores", "Aplicar e alterar configuração de coletores.", "Coletores", "critical"),
        _permission("cgnat.view", "Visualizar CGNAT", "Consultar lotes e mapeamentos CGNAT.", "CGNAT", "low"),
        _permission("cgnat.import", "Importar CGNAT", "Criar e processar importações CGNAT.", "CGNAT", "high"),
        _permission("cgnat.manage", "Administrar CGNAT", "Aprovar, ativar, rejeitar e desativar lotes.", "CGNAT", "critical"),
        _permission("grafana.view", "Visualizar integração Grafana", "Consultar estado e catálogos da integração.", "Grafana", "low"),
        _permission("grafana.manage", "Administrar integração Grafana", "Alterar e publicar integrações Grafana.", "Grafana", "high"),
        _permission("users.view", "Visualizar usuários", "Consultar usuários, perfis e permissões.", "Usuários", "medium"),
        _permission("users.create", "Criar usuários", "Criar contas com senha temporária.", "Usuários", "high"),
        _permission("users.edit", "Editar usuários", "Editar dados e perfil de usuários.", "Usuários", "high"),
        _permission("users.disable", "Desativar usuários", "Ativar ou desativar contas.", "Usuários", "critical"),
        _permission("users.delete", "Excluir usuários", "Executar exclusão lógica confirmada.", "Usuários", "critical"),
        _permission("users.reset_password", "Redefinir senhas", "Definir senha temporária e revogar sessões.", "Usuários", "critical"),
        _permission("users.manage_permissions", "Gerenciar permissões", "Alterar perfis e overrides individuais.", "Usuários", "critical"),
        _permission("settings.view", "Visualizar configurações", "Consultar configurações do sistema.", "Configurações", "low"),
        _permission("settings.manage", "Administrar configurações", "Alterar configurações críticas do sistema.", "Configurações", "critical"),
        _permission("audit.view", "Visualizar auditoria", "Consultar ações administrativas e de autenticação.", "Auditoria", "high"),
    )
}


VIEWER_PERMISSIONS = {
    "dashboard.view",
    "anomalies.view",
    "mitigations.view",
    "bgp.view",
    "sensors.view",
    "collectors.view",
    "cgnat.view",
    "grafana.view",
    "settings.view",
}

OPERATOR_PERMISSIONS = VIEWER_PERMISSIONS | {
    "dashboard.edit",
    "anomalies.manage",
    "mitigations.apply",
    "mitigations.withdraw",
    "cgnat.import",
}

ROLE_TEMPLATES: dict[str, dict[str, Any]] = {
    "admin": {
        "name": "Administrador",
        "description": "Acesso administrativo completo.",
        "permissions": set(PERMISSION_CATALOG),
    },
    "operator": {
        "name": "Operador",
        "description": "Operação cotidiana sem administração de usuários.",
        "permissions": OPERATOR_PERMISSIONS,
    },
    "viewer": {
        "name": "Visualizador",
        "description": "Acesso somente leitura.",
        "permissions": VIEWER_PERMISSIONS,
    },
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone() is not None


def _ensure_column(
    conn: sqlite3.Connection,
    table: str,
    name: str,
    definition: str,
) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")


def ensure_auth_schema(conn: sqlite3.Connection) -> None:
    """Create the RBAC/session schema without changing legacy password hashes."""

    had_rbac_schema = _table_exists(conn, "roles")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    additions = {
        "display_name": "display_name TEXT NOT NULL DEFAULT ''",
        "email": "email TEXT NOT NULL DEFAULT ''",
        "failed_login_attempts": "failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "locked_until": "locked_until TEXT",
        "last_login_at": "last_login_at TEXT",
        "password_changed_at": "password_changed_at TEXT",
        "created_by": "created_by INTEGER",
        "updated_by": "updated_by INTEGER",
        "auth_version": "auth_version INTEGER NOT NULL DEFAULT 0",
        "deleted_at": "deleted_at TEXT",
    }
    for name, definition in additions.items():
        _ensure_column(conn, "users", name, definition)

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            system_role INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_key TEXT NOT NULL,
            allowed INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(role_id, permission_key),
            FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_permission_overrides (
            user_id INTEGER NOT NULL,
            permission_key TEXT NOT NULL,
            effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(user_id, permission_key),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            revoked_reason TEXT NOT NULL DEFAULT '',
            last_seen_at TEXT,
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            actor_username TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL DEFAULT '',
            resource_id TEXT NOT NULL DEFAULT '',
            success INTEGER NOT NULL DEFAULT 1,
            ip TEXT NOT NULL DEFAULT '',
            user_agent TEXT NOT NULL DEFAULT '',
            correlation_id TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, revoked_at, expires_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at DESC)")

    now = utc_now_iso()
    for key, template in ROLE_TEMPLATES.items():
        conn.execute(
            """
            INSERT INTO roles(key, name, description, system_role, active, created_at, updated_at)
            VALUES (?, ?, ?, 1, 1, ?, ?)
            ON CONFLICT(key) DO NOTHING
            """,
            (key, template["name"], template["description"], now, now),
        )
        role_id = int(conn.execute("SELECT id FROM roles WHERE key = ?", (key,)).fetchone()[0])
        for permission_key in sorted(template["permissions"]):
            conn.execute(
                """
                INSERT INTO role_permissions(role_id, permission_key, allowed)
                VALUES (?, ?, 1)
                ON CONFLICT(role_id, permission_key) DO NOTHING
                """,
                (role_id, permission_key),
            )

    legacy_roles = conn.execute(
        "SELECT DISTINCT role FROM users WHERE trim(COALESCE(role, '')) <> ''"
    ).fetchall()
    for row in legacy_roles:
        role_key = str(row[0])
        conn.execute(
            """
            INSERT INTO roles(key, name, description, system_role, active, created_at, updated_at)
            VALUES (?, ?, 'Perfil legado preservado.', 0, 1, ?, ?)
            ON CONFLICT(key) DO NOTHING
            """,
            (role_key, role_key.replace("_", " ").title(), now, now),
        )
    if not had_rbac_schema:
        legacy_users = conn.execute("SELECT id, role, active FROM users ORDER BY id").fetchall()
        has_legacy_admin = any(str(row[1]) == "admin" and bool(row[2]) for row in legacy_users)
        bootstrap_admin = next((row for row in legacy_users if bool(row[2])), None)
        if not has_legacy_admin and bootstrap_admin is not None:
            conn.execute(
                "UPDATE users SET role = 'admin' WHERE id = ?",
                (int(bootstrap_admin[0]),),
            )
    conn.execute("UPDATE users SET role = 'viewer' WHERE trim(COALESCE(role, '')) = ''")
    conn.execute("UPDATE users SET display_name = username WHERE trim(COALESCE(display_name, '')) = ''")
    conn.execute(
        """
        UPDATE users
        SET password_changed_at = COALESCE(password_changed_at, updated_at, created_at)
        WHERE password_changed_at IS NULL
        """
    )


def effective_permissions(conn: sqlite3.Connection, user: Any) -> set[str]:
    if user is None or not bool(user["active"]):
        return set()
    inherited = {
        str(row[0])
        for row in conn.execute(
            """
            SELECT rp.permission_key
            FROM roles AS r
            JOIN role_permissions AS rp ON rp.role_id = r.id
            WHERE r.key = ? AND r.active = 1 AND rp.allowed = 1
            """,
            (str(user["role"]),),
        ).fetchall()
        if str(row[0]) in PERMISSION_CATALOG
    }
    overrides = conn.execute(
        "SELECT permission_key, effect FROM user_permission_overrides WHERE user_id = ?",
        (int(user["id"]),),
    ).fetchall()
    allowed = {str(row[0]) for row in overrides if str(row[1]) == "allow"}
    denied = {str(row[0]) for row in overrides if str(row[1]) == "deny"}
    return (inherited | allowed) - denied


def permission_details(conn: sqlite3.Connection, user: Any) -> list[dict[str, Any]]:
    role_permissions = {
        str(row[0])
        for row in conn.execute(
            """
            SELECT rp.permission_key
            FROM roles AS r
            JOIN role_permissions AS rp ON rp.role_id = r.id
            WHERE r.key = ? AND r.active = 1 AND rp.allowed = 1
            """,
            (str(user["role"]),),
        ).fetchall()
    }
    overrides = {
        str(row[0]): str(row[1])
        for row in conn.execute(
            "SELECT permission_key, effect FROM user_permission_overrides WHERE user_id = ?",
            (int(user["id"]),),
        ).fetchall()
    }
    effective = effective_permissions(conn, user)
    return [
        {
            **metadata,
            "inherited": key in role_permissions,
            "override": overrides.get(key),
            "effective": key in effective,
        }
        for key, metadata in PERMISSION_CATALOG.items()
    ]


def active_admin_ids(conn: sqlite3.Connection) -> list[int]:
    rows = conn.execute("SELECT * FROM users WHERE active = 1 AND deleted_at IS NULL").fetchall()
    return [
        int(row["id"])
        for row in rows
        if "users.manage_permissions" in effective_permissions(conn, row)
    ]


def sanitize_audit_metadata(value: Any) -> Any:
    sensitive = {"password", "password_hash", "token", "authorization", "secret", "api_key"}
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]"
                if any(marker in str(key).lower() for marker in sensitive)
                else sanitize_audit_metadata(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_audit_metadata(item) for item in value]
    return value


def audit_action(
    conn: sqlite3.Connection,
    *,
    user_id: int | None,
    actor_username: str,
    action: str,
    resource_type: str = "",
    resource_id: str | int = "",
    success: bool = True,
    ip: str = "",
    user_agent: str = "",
    correlation_id: str = "",
    metadata: Any = None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO audit_log(
            user_id, actor_username, action, resource_type, resource_id,
            success, ip, user_agent, correlation_id, metadata_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            actor_username[:200],
            action[:200],
            resource_type[:100],
            str(resource_id)[:200],
            int(bool(success)),
            ip[:200],
            user_agent[:500],
            correlation_id[:100],
            json.dumps(sanitize_audit_metadata(metadata or {}), sort_keys=True, default=str),
            utc_now_iso(),
        ),
    )
    return int(cursor.lastrowid)


def revoke_user_sessions(
    conn: sqlite3.Connection,
    user_id: int,
    reason: str,
    *,
    except_session_id: str = "",
) -> int:
    now = utc_now_iso()
    params: list[Any] = [now, reason[:200], int(user_id)]
    where = "user_id = ? AND revoked_at IS NULL"
    if except_session_id:
        where += " AND id <> ?"
        params.append(except_session_id)
    cursor = conn.execute(
        f"UPDATE auth_sessions SET revoked_at = ?, revoked_reason = ? WHERE {where}",
        params,
    )
    return max(0, int(cursor.rowcount or 0))


def session_is_active(
    conn: sqlite3.Connection,
    session_id: str,
    user_id: int,
    encoded_token: str,
    now: str,
) -> bool:
    row = conn.execute(
        """
        SELECT id
        FROM auth_sessions
        WHERE id = ? AND user_id = ? AND token_hash = ?
          AND revoked_at IS NULL AND expires_at > ?
        """,
        (session_id, int(user_id), token_hash(encoded_token), now),
    ).fetchone()
    if row is None:
        return False
    conn.execute(
        "UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?",
        (now, session_id),
    )
    return True
