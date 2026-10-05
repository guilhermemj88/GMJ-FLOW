import React, { useEffect, useRef, useState } from 'react';

export const TOKEN_KEY = 'gmjflow_preview_token';
export const ENV_LABEL = 'PREVIEW V2 · DADOS REAIS · SOMENTE LEITURA';

export function token() { return localStorage.getItem(TOKEN_KEY) || ''; }
export function setToken(value) {
  if (value) localStorage.setItem(TOKEN_KEY, value);
  else localStorage.removeItem(TOKEN_KEY);
}

/**
 * Gate de permissão do front. Fonte única = backend (`/api/auth/me` entrega
 * `permissions` efetivas já calculadas). O front NUNCA recalcula RBAC.
 */
export function hasPermission(user, code) {
  if (!code) return true;
  return Array.isArray(user?.permissions) && user.permissions.includes(code);
}

export async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;
  if (options.body && typeof options.body !== 'string') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    setToken('');
    window.dispatchEvent(new Event('gmjflow-auth-expired'));
    throw new Error('Sessão expirada. Entre novamente.');
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const data = await res.json();
      detail = typeof data?.detail === 'string' ? data.detail : (data?.detail?.message || detail);
    } catch (_) { /* ignore */ }
    throw new Error(detail || `HTTP ${res.status}`);
  }
  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

export function fmtBits(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '—';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let scaled = Math.abs(n);
  let i = 0;
  while (scaled >= 1000 && i < units.length - 1) { scaled /= 1000; i += 1; }
  const value = n / Math.pow(1000, i);
  return `${value.toFixed(i === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtPps(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '—';
  const units = ['pps', 'Kpps', 'Mpps'];
  let scaled = Math.abs(n);
  let i = 0;
  while (scaled >= 1000 && i < units.length - 1) { scaled /= 1000; i += 1; }
  const value = n / Math.pow(1000, i);
  return `${value.toFixed(i === 0 ? 0 : value >= 100 ? 0 : 1)} ${units[i]}`;
}

export function fmtTime(v) {
  if (!v) return '—';
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return String(v);
  return d.toLocaleString('pt-BR');
}

export function fmtNumber(v, digits = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '—';
  return n.toLocaleString('pt-BR', { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

export function statusTone(status) {
  const s = String(status || '').toLowerCase();
  if (['advertised', 'active', 'established', 'online', 'ok', 'success', 'healthy', 'confirmed', 'available', 'up'].includes(s)) return 'success';
  if (['critical', 'failed', 'down', 'withdraw_failed', 'error'].includes(s)) return 'critical';
  if (['warning', 'pending', 'pending_approval', 'queued', 'applying', 'stale', 'not_checked'].includes(s)) return 'warning';
  return 'info';
}

export function severityTone(severity) {
  const s = String(severity || '').toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'warning';
  if (s === 'MEDIUM' || s === 'WARNING') return 'warning';
  if (s === 'LOW' || s === 'INFO') return 'info';
  return 'info';
}

export function Badge({ children, tone = 'info', pulse = false }) {
  return <span className={`badge ${tone}`}>{pulse ? <i className="status-dot pulse" /> : null}{children}</span>;
}

export function useApi(path, { enabled = true, deps = [] } = {}) {
  const [state, setState] = useState({ loading: true, data: null, error: null });
  const seq = useRef(0);
  useEffect(() => {
    if (!enabled) { setState({ loading: false, data: null, error: null }); return undefined; }
    const id = ++seq.current;
    setState((s) => ({ ...s, loading: true, error: null }));
    api(path)
      .then((data) => { if (seq.current === id) setState({ loading: false, data, error: null }); })
      .catch((err) => { if (seq.current === id) setState({ loading: false, data: null, error: err.message }); });
    return () => { seq.current += 1; };
  }, [path, enabled, ...deps]);
  return state;
}

export function Loading() { return <div className="subtle" style={{ padding: '14px 16px' }}>Carregando dados reais…</div>; }

export function ErrorBox({ message }) {
  return <div className="error-box"><Badge tone="warning">Indisponível</Badge><span>{message || 'Não foi possível carregar.'}</span></div>;
}

export function Panel({ title, subtitle, badge, badgeTone = 'info', actions, filters, children }) {
  return (
    <div className="data-panel">
      <div className="panel-title">
        <div><b>{title}</b>{subtitle ? <span>{subtitle}</span> : null}</div>
        <div className="panel-actions">{actions}{badge != null ? <Badge tone={badgeTone}>{badge}</Badge> : null}</div>
      </div>
      {filters ? <div className="panel-filters">{filters}</div> : null}
      {children}
    </div>
  );
}

export function Table({ columns, rows, keyFor, empty = 'Nenhum registro.', onRowClick }) {
  const list = Array.isArray(rows) ? rows : [];
  return (
    <div className="table-scroll">
      <table>
        <thead><tr>{columns.map((c) => <th key={c.key}>{c.label}</th>)}</tr></thead>
        <tbody>
          {list.length === 0 ? (
            <tr><td colSpan={columns.length} className="subtle">{empty}</td></tr>
          ) : list.map((row, i) => (
            <tr
              key={keyFor ? keyFor(row, i) : i}
              className={onRowClick ? 'row-clickable' : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
            >
              {columns.map((c) => {
                const raw = c.render ? c.render(row) : row[c.key];
                return <td key={c.key}>{raw == null || raw === '' ? '—' : raw}</td>;
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Primitivos do BLOCO 1 (Mitigação + BGP/Conectores).
 *
 * Pequenos de propósito: compartilham aparência e semântica entre as duas
 * páginas, sem criar framework interno nem alterar as telas já concluídas.
 */

/** Tons para os estados REAIS do backend (execuções, announcements, conectores, RTBH). */
export function stateTone(value) {
  const s = String(value ?? '').toLowerCase();
  if (['active', 'advertised', 'established', 'ok', 'valid', 'enabled', 'sent', 'approved', 'allow_auto', 'safe', 'confirmed'].includes(s)) {
    return 'success';
  }
  if (['blocked', 'failed', 'failed_withdraw', 'peer_down', 'down', 'rejected', 'deny', 'danger', 'invalid_connector', 'unsafe', 'critical'].includes(s)) {
    return 'critical';
  }
  if (['queued', 'applying', 'pending_approval', 'prepared', 'dry_run', 'withdraw_pending', 'caution', 'review_required', 'disabled', 'deprecated', 'manual_approval', 'warning'].includes(s)) {
    return 'warning';
  }
  if (['withdrawn', 'expired', 'cancelled', 'deduplicated', 'suggest_only', 'not_checked'].includes(s)) {
    return 'info';
  }
  return 'info';
}

export function StatusDot({ tone = 'info', pulse = false }) {
  return <i className={`status-dot ${tone}${pulse ? ' pulse' : ''}`} />;
}

/** Link de entidade entre páginas (anomalia, execução, announcement, connector). */
export function EntityLink({ label, onClick, title, tone = 'info' }) {
  if (!onClick) return <span className={`entity-link ${tone}`}>{label}</span>;
  return (
    <button type="button" className={`entity-link ${tone}`} title={title} onClick={onClick}>
      {label}
    </button>
  );
}

/**
 * Ação que existe na produção mas está bloqueada no preview (default-deny).
 * Fica visível e desabilitada explicando o motivo — nunca silenciosamente ativa.
 */
export function ReadOnlyAction({ label, reason, policy = 'B' }) {
  const className = policy === 'C' ? 'critical' : policy === 'A' ? 'warning' : '';
  return (
    <button type="button" className={`control readonly ${className}`} disabled title={reason || 'Bloqueado no PREVIEW V2 (somente leitura)'}>
      {label}
    </button>
  );
}

/** Cronologia: usa sempre eventos reais (bgp_announcement_events, timestamps do payload). */
export function Timeline({ items }) {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return <p className="subtle">Sem eventos registrados.</p>;
  return (
    <ol className="timeline">
      {list.map((item, index) => (
        <li key={`${item.title}-${index}`} className={item.tone || 'info'}>
          <i className={`timeline-dot ${item.tone || 'info'}`} />
          <div>
            <b>{item.title}</b>
            {item.at ? <code>{item.at}</code> : null}
            {item.detail ? <small>{item.detail}</small> : null}
          </div>
        </li>
      ))}
    </ol>
  );
}

export function EmptyState({ title = 'Nada aqui', hint }) {
  return (
    <div className="empty-state">
      <b>{title}</b>
      {hint ? <span>{hint}</span> : null}
    </div>
  );
}

export function Pagination({ total = 0, limit = 100, offset = 0, onChange }) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + limit, total);
  const canPrev = offset > 0;
  const canNext = to < total;
  return (
    <div className="pagination">
      <span>{from}–{to} de {fmtNumber(total)}</span>
      <div>
        <button type="button" className="control" disabled={!canPrev} onClick={() => onChange(Math.max(0, offset - limit))}>Anterior</button>
        <button type="button" className="control" disabled={!canNext} onClick={() => onChange(offset + limit)}>Próxima</button>
      </div>
    </div>
  );
}

/** Lista rótulo/valor (mono) para drawers — sem inventar campo que não veio do backend. */
export function KeyValues({ items }) {
  const list = (Array.isArray(items) ? items : []).filter(Boolean);
  if (!list.length) return <p className="subtle">Sem dados nesta seção.</p>;
  return (
    <div className="kv-grid">
      {list.map(([label, value, tone]) => (
        <div key={label}>
          <span>{label}</span>
          <b className={tone ? `tone-${tone}` : undefined}>{value == null || value === '' ? '—' : value}</b>
        </div>
      ))}
    </div>
  );
}

/**
 * Nível de evidência da etapa. A UI nunca promove uma evidência fraca:
 * "verificado" só quando o backend entregou o dado correspondente.
 */
export function EvidenceLevel({ verified, label, detail }) {
  return (
    <div className={`evidence-level ${verified ? 'verified' : 'unverified'}`}>
      <Badge tone={verified ? 'success' : 'info'}>{verified ? 'verificado' : 'não verificado'}</Badge>
      <div><b>{label}</b>{detail ? <small>{detail}</small> : null}</div>
    </div>
  );
}
