import React, { useMemo, useState } from 'react';
import {
  Badge, EmptyState, ErrorBox, Loading, Pagination, Panel, ReadOnlyAction, Table,
  fmtNumber, fmtTime, hasPermission, useApi,
} from './shared.jsx';

/**
 * P0-A — Usuários e Acessos (estrutura/navegação + listagem READ-ONLY).
 *
 * Fonte canônica: GET /api/v1/users | /api/v1/roles | /api/v1/permissions.
 * Nenhuma escrita é executada: os botões de mutação existem apenas como
 * ReadOnlyAction (bloqueio default-deny do preview :8081).
 *
 * Fora do escopo deste lote (lotes seguintes): detalhe do usuário, matriz de
 * permissões, criação/edição, reset/revoke/delete reais e auditoria completa.
 */
const PAGE_SIZE = 25;
const EMPTY_FILTERS = { search: '', status: '', role: '' };

function isLocked(user) {
  return String(user?.status || '').toLowerCase() === 'locked';
}

function statusLabel(user) {
  if (isLocked(user)) return 'Bloqueado';
  return user?.active ? 'Ativo' : 'Desativado';
}

function statusTone(user) {
  if (isLocked(user)) return 'warning';
  return user?.active ? 'success' : 'info';
}

export default function UsersPage({ user }) {
  const allowed = hasPermission(user, 'users.view');
  const [draft, setDraft] = useState(EMPTY_FILTERS);
  const [applied, setApplied] = useState(EMPTY_FILTERS);
  const [offset, setOffset] = useState(0);

  const rolesApi = useApi('/api/v1/roles', { enabled: allowed });
  const permissionsApi = useApi('/api/v1/permissions', { enabled: allowed });
  const roles = rolesApi.data?.items || [];
  const permissions = permissionsApi.data?.items || [];

  const usersPath = useMemo(() => {
    const params = new URLSearchParams({ offset: String(offset), limit: String(PAGE_SIZE) });
    if (applied.search) params.set('search', applied.search);
    if (applied.status) params.set('status', applied.status);
    if (applied.role) params.set('role', applied.role);
    return `/api/v1/users?${params.toString()}`;
  }, [offset, applied]);
  const usersApi = useApi(usersPath, { enabled: allowed, deps: [usersPath] });

  if (!allowed) {
    return (
      <div className="page">
        <EmptyState title="Acesso restrito" hint="Sua conta não possui a permissão users.view." />
      </div>
    );
  }

  const items = usersApi.data?.items || [];
  const total = Number(usersApi.data?.total || 0);
  const roleLabel = (key) => roles.find((role) => role.key === key)?.name || key || '—';
  const setField = (key, value) => setDraft((prev) => ({ ...prev, [key]: value }));
  const applyFilters = () => { setApplied({ ...draft }); setOffset(0); };
  const clearFilters = () => { setDraft(EMPTY_FILTERS); setApplied(EMPTY_FILTERS); setOffset(0); };

  const writeActions = (row) => {
    const actions = [];
    if (hasPermission(user, 'users.edit')) {
      actions.push(<ReadOnlyAction key="edit" label="Editar" reason="PATCH /api/v1/users/{id} — escrita; bloqueado no preview" />);
    }
    if (hasPermission(user, 'users.disable')) {
      actions.push(
        <ReadOnlyAction
          key="toggle"
          label={row.active ? 'Desativar' : 'Ativar'}
          reason={`POST /api/v1/users/{id}/${row.active ? 'disable' : 'enable'} — escrita; bloqueado no preview`}
        />,
      );
    }
    if (hasPermission(user, 'users.reset_password')) {
      actions.push(<ReadOnlyAction key="reset" label="Redefinir senha" reason="POST /api/v1/users/{id}/reset-password — escrita; bloqueado no preview" />);
    }
    if (hasPermission(user, 'users.edit')) {
      actions.push(<ReadOnlyAction key="revoke" label="Revogar sessões" reason="POST /api/v1/users/{id}/revoke-sessions — escrita; bloqueado no preview" policy="C" />);
    }
    if (hasPermission(user, 'audit.view')) {
      actions.push(<ReadOnlyAction key="audit" label="Auditoria" reason="GET /api/v1/audit/users/{id} disponível; modal completo entra no lote P1-B" policy="A" />);
    }
    if (hasPermission(user, 'users.delete')) {
      actions.push(<ReadOnlyAction key="delete" label="Excluir" reason="DELETE /api/v1/users/{id} — escrita; bloqueado no preview" policy="C" />);
    }
    return actions.length ? <div className="row-actions">{actions}</div> : <span className="subtle">—</span>;
  };

  const columns = [
    {
      key: 'username',
      label: 'Usuário',
      render: (row) => (
        <div><b>{row.username}</b>{row.email ? <span className="subtle" style={{ display: 'block' }}>{row.email}</span> : null}</div>
      ),
    },
    { key: 'display_name', label: 'Nome', render: (row) => row.display_name || '—' },
    { key: 'role', label: 'Perfil', render: (row) => roleLabel(row.role) },
    { key: 'status', label: 'Status', render: (row) => <Badge tone={statusTone(row)}>{statusLabel(row)}</Badge> },
    { key: 'last_login_at', label: 'Último login', render: (row) => (row.last_login_at ? fmtTime(row.last_login_at) : '—') },
    { key: 'must_change_password', label: 'Troca obrigatória', render: (row) => (row.must_change_password ? 'Sim' : 'Não') },
    { key: 'active_sessions', label: 'Sessões', render: (row) => fmtNumber(row.active_sessions || 0) },
    { key: 'actions', label: 'Ações', render: (row) => writeActions(row) },
  ];

  return (
    <div className="page">
      <div className="v2-readonly-note">
        <Badge tone="critical">SOMENTE LEITURA</Badge>
        <span>
          Listagem real via <code>GET /api/v1/users</code> (P0-A). Ações de escrita aparecem apenas como
          <b> ReadOnlyAction</b> — nenhuma mutação é executada no preview.
        </span>
      </div>

      <Panel
        title="Usuários e Acessos"
        subtitle="Contas, perfis e permissões reais · paginação server-side · P0-A (listagem)"
        badge={usersApi.error ? 'Indisponível' : `${fmtNumber(total)} usuário(s)`}
        badgeTone={usersApi.error ? 'warning' : 'info'}
        actions={
          <>
            <span className="subtle">{roles.length} perfil(is) · {permissions.length} permissão(ões)</span>
            {hasPermission(user, 'audit.view')
              ? <ReadOnlyAction label="Auditoria" reason="GET /api/v1/audit disponível; modal completo entra no lote P1-B" policy="A" />
              : null}
            {hasPermission(user, 'users.create')
              ? <ReadOnlyAction label="Novo usuário" reason="POST /api/v1/users — escrita; bloqueado no preview" /> 
              : null}
          </>
        }
        filters={
          <div className="v2-filters">
            <label className="v2-field">
              <span>Pesquisar</span>
              <input
                value={draft.search}
                placeholder="username, nome ou e-mail"
                onChange={(event) => setField('search', event.target.value)}
                onKeyDown={(event) => { if (event.key === 'Enter') applyFilters(); }}
              />
            </label>
            <label className="v2-field">
              <span>Status</span>
              <select value={draft.status} onChange={(event) => setField('status', event.target.value)}>
                <option value="">Todos</option>
                <option value="active">Ativos</option>
                <option value="disabled">Desativados</option>
              </select>
            </label>
            <label className="v2-field">
              <span>Perfil</span>
              <select value={draft.role} onChange={(event) => setField('role', event.target.value)}>
                <option value="">Todos</option>
                {roles.filter((role) => role.active).map((role) => (
                  <option key={role.key} value={role.key}>{role.name}</option>
                ))}
              </select>
            </label>
            <button type="button" className="control" onClick={applyFilters}>Filtrar</button>
            <button type="button" className="control" onClick={clearFilters}>Limpar</button>
          </div>
        }
      >
        {usersApi.error ? <ErrorBox message={usersApi.error} /> : null}
        {rolesApi.error ? <ErrorBox message={`Perfis: ${rolesApi.error}`} /> : null}
        {permissionsApi.error ? <ErrorBox message={`Permissões: ${permissionsApi.error}`} /> : null}
        {usersApi.loading ? <Loading /> : (
          <>
            <Table
              columns={columns}
              rows={items}
              keyFor={(row) => row.id}
              empty="Nenhum usuário encontrado para os filtros atuais."
            />
            <Pagination total={total} limit={PAGE_SIZE} offset={offset} onChange={setOffset} />
          </>
        )}
      </Panel>
    </div>
  );
}
