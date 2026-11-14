'use client';

import { useState } from 'react';
import { Empty } from '../components/ui';
import { api } from '../lib/api';
import { usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';
import { ROLE_INFO, type AuditEvent, type Role } from '../lib/types';

const CATEGORIES = [['', 'Everything'], ['auth', 'Sign-ins & passwords'], ['user', 'Users & roles'], ['agent', 'Agents'], ['enroll', 'Install links'], ['server', 'Servers & tokens'], ['logs', 'Log access'], ['k8s', 'Kubernetes'], ['purge', 'Data purges'], ['channel', 'Alert channels'], ['service', 'Service monitors'], ['schedule', 'Scheduled messages']];

const LABELS: Record<string, string> = {
  'auth.login': 'Sign-in', 'auth.logout': 'Sign-out', 'auth.password_change': 'Password change', 'auth.email_change': 'Email change',
  'user.create': 'User created', 'user.update': 'User changed', 'user.delete': 'User deleted',
  'server.create': 'Server added', 'server.update': 'Server edited', 'server.delete': 'Server removed',
  'server.token_rotate': 'Token rotation started', 'server.token_revoke': 'Token revoked',
  'agent.enroll': 'Agent registered', 'agent.token_rotated': 'Agent switched token', 'agent.ip_changed': 'Agent address changed', 'agent.auth_failed': 'Agent rejected',
  'enroll.link_create': 'Install link created', 'enroll.link_revoke': 'Install link revoked', 'logs.read': 'Logs viewed', 'logs.denied': 'Log access blocked', 'server.log_policy': 'Log policy changed',
  'k8s.register': 'Cluster registered', 'k8s.cluster_update': 'Cluster edited', 'k8s.cluster_delete': 'Cluster removed', 'k8s.token_rotate': 'Cluster token rotation', 'k8s.token_revoke': 'Cluster token revoked',
  'k8s.logs.read': 'Pod logs viewed', 'k8s.logs.denied': 'Pod logs blocked', 'k8s.log_policy': 'Cluster log policy changed',
  'service.create': 'Service monitor added', 'service.update': 'Service monitor changed', 'service.delete': 'Service monitor deleted', 'channel.test': 'Channel test sent',
  'schedule.create': 'Scheduled message added', 'schedule.update': 'Scheduled message changed', 'schedule.delete': 'Scheduled message deleted', 'schedule.send_now': 'Scheduled message sent now',
  'purge.settings': 'Retention changed', 'purge.manual': 'Manual purge', 'purge.scheduled': 'Scheduled purge',
  'channel.create': 'Channel added', 'channel.update': 'Channel edited', 'channel.delete': 'Channel removed',
};

export function Audit() {
  const [category, setCategory] = useState('');
  const [failures, setFailures] = useState(false);
  const [q, setQ] = useState('');
  const [applied, setApplied] = useState('');
  const { value, error } = usePoll(() => api<AuditEvent[]>(`/audit?limit=300&category=${category}&failures=${failures}&q=${encodeURIComponent(applied)}`), [category, failures, applied], 10000);

  return (
    <>
      <div className="topbar"><div><h1>Audit log</h1><p className="muted sm">Who did what, from where. Append-only: events cannot be edited or deleted. Kept for a year.</p></div></div>
      <form className="lv-filters" style={{ border: '1px solid var(--line)', borderRadius: 'var(--radius)', marginBottom: 14, background: 'var(--surface)' }} onSubmit={e => { e.preventDefault(); setApplied(q); }}>
        <select className="lv-select" value={category} onChange={e => setCategory(e.target.value)} aria-label="Category">{CATEGORIES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
        <label className="lv-search"><input value={q} onChange={e => setQ(e.target.value)} placeholder="Search person, address, server, detail…" maxLength={100} aria-label="Search" /></label>
        <label className="check"><input type="checkbox" checked={failures} onChange={e => setFailures(e.target.checked)} />Only failures</label>
        <button className="btn primary sm">Search</button>
      </form>
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        {error ? <div className="err" style={{ margin: 14 }}>{error}</div> : !value ? <p className="muted" style={{ padding: 18 }}>Loading…</p> : value.length === 0 ? <Empty title="No matching events" /> : (
          <div style={{ overflowX: 'auto' }}><table className="tbl"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th className="hide-sm">Detail</th><th className="hide-sm">From</th></tr></thead><tbody>
            {value.map(e => (
              <tr key={e.id} style={e.success ? undefined : { background: 'color-mix(in srgb, var(--bad) 7%, transparent)' }}>
                <td className="sm" style={{ whiteSpace: 'nowrap' }} title={new Date(e.ts).toLocaleString()}>{timeAgo(e.ts)}</td>
                <td><div className="name" style={{ fontSize: 13 }}>{e.actor || 'system'}{e.actor_role && <> <span className={`role-pill ${e.actor_role}`}>{ROLE_INFO[e.actor_role as Role]?.label ?? e.actor_role}</span></>}</div></td>
                <td className="sm"><b style={{ color: e.success ? 'var(--ink)' : 'var(--bad)' }}>{LABELS[e.action] ?? e.action}</b>{!e.success && <span className="bad"> · failed</span>}</td>
                <td className="sm mono muted">{e.target}</td>
                <td className="hide-sm sm" style={{ maxWidth: 380 }}>{e.detail}</td>
                <td className="hide-sm sm mono muted">{e.ip}</td>
              </tr>))}
          </tbody></table></div>
        )}
      </div>
    </>
  );
}
