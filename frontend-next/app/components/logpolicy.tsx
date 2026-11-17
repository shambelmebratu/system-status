'use client';

import { FormEvent, useEffect, useState } from 'react';
import { api, put } from '../lib/api';
import { useApp } from '../lib/app';
import { Icon, Modal } from './ui';

type Policy = {
  ssh?: { enabled: boolean; history: boolean };
  docker: { enabled: boolean; include: string[]; exclude: string[] };
  journal: { enabled: boolean; units: string[] };
  files: { enabled: boolean; mode: 'all' | 'selected'; categories: string[]; custom: string[] };
};
type Category = { id: string; label: string; hint: string };

const EVERYTHING: Policy = { docker: { enabled: true, include: ['*'], exclude: [] }, journal: { enabled: true, units: ['*'] }, files: { enabled: true, mode: 'all', categories: [], custom: [] } };
const PRESETS: { label: string; hint: string; policy: Policy }[] = [
  { label: 'Everything', hint: 'The default: every log the agent can read', policy: EVERYTHING },
  { label: 'Containers only', hint: 'Docker container logs; no journal, no files', policy: { ...EVERYTHING, journal: { enabled: false, units: [] }, files: { enabled: false, mode: 'all', categories: [], custom: [] } } },
  { label: 'Web & applications', hint: 'Web server and app logs, plus containers; no system/auth logs', policy: { docker: { enabled: true, include: ['*'], exclude: [] }, journal: { enabled: false, units: [] }, files: { enabled: true, mode: 'selected', categories: ['web', 'apps'], custom: [] } } },
  { label: 'Nothing', hint: 'Turn log access off for this server', policy: { docker: { enabled: false, include: [], exclude: [] }, journal: { enabled: false, units: [] }, files: { enabled: false, mode: 'all', categories: [], custom: [] } } },
];

const lines = (v: string) => v.split(/[\s,]+/).map(x => x.trim()).filter(Boolean);

/** One pattern per line. Keeps what you type as-is (so Enter and spaces work) and reports the parsed list. */
function PatternList({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder: string }) {
  const [text, setText] = useState(value.join('\n'));
  return <textarea rows={3} value={text} onChange={e => { setText(e.target.value); onChange(lines(e.target.value)); }} placeholder={placeholder} style={{ width: '100%', fontFamily: 'var(--mono)', fontSize: 12 }} />;
}
const summary = (p: Policy) => [
  `Containers: ${!p.docker.enabled ? 'off' : p.docker.include.join(', ') === '*' && !p.docker.exclude.length ? 'all' : 'selected'}`,
  `Journal: ${!p.journal.enabled ? 'off' : p.journal.units.join(', ') === '*' ? 'all' : 'selected units'}`,
  `SSH: ${p.ssh?.enabled === false ? 'off' : p.ssh?.history === false ? 'sessions only' : 'sessions + commands'}`,
  `Files: ${!p.files.enabled ? 'off' : p.files.mode === 'all' ? 'all' : `${p.files.categories.length} types${p.files.custom.length ? ` + ${p.files.custom.length} paths` : ''}`}`,
];

/** Which logs this server's agent may expose. Enforced by the control plane AND by the agent itself. */
export function LogPolicyCard({ serverId }: { serverId: number }) {
  const { isAdmin, toast } = useApp();
  const [data, setData] = useState<{ policy: Policy; restricted: boolean } | null>(null);
  const [editing, setEditing] = useState(false);
  const load = () => api<{ policy: Policy; restricted: boolean }>(`/servers/${serverId}/log-policy`).then(setData).catch(() => undefined);
  useEffect(() => { void load(); }, [serverId]);   // eslint-disable-line react-hooks/exhaustive-deps
  if (!data) return null;
  return (
    <section className="card">
      <div className="card-head"><h2>Log access</h2><span className="grow" />{data.restricted && <span className="tag">restricted</span>}{isAdmin && <button className="btn sm" onClick={() => setEditing(true)}>Configure</button>}</div>
      <p className="muted sm" style={{ marginBottom: 10 }}>Which logs this server&apos;s agent may expose. Logs are read on demand and never stored.</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>{summary(data.policy).map(l => <span key={l} className="sm">{l}</span>)}</div>
      {!isAdmin && <p className="muted sm" style={{ marginTop: 10 }}>Only admins can change this.</p>}
      {editing && <PolicyEditor serverId={serverId} initial={data.policy} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); toast('Log access policy saved. The agent applies it at its next report.'); void load(); }} />}
    </section>
  );
}

function PolicyEditor({ serverId, initial, onClose, onSaved }: { serverId: number; initial: Policy; onClose: () => void; onSaved: () => void }) {
  const [p, setP] = useState<Policy>(initial);
  const [catalog, setCatalog] = useState<Category[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { api<{ file_categories: Category[] }>('/log-policy/catalog').then(c => setCatalog(c.file_categories)).catch(() => undefined); }, []);
  const toggleCat = (id: string) => setP({ ...p, files: { ...p.files, categories: p.files.categories.includes(id) ? p.files.categories.filter(c => c !== id) : [...p.files.categories, id] } });

  async function save(event: FormEvent) {
    event.preventDefault(); setError(''); setBusy(true);
    try { await put(`/servers/${serverId}/log-policy`, p); onSaved(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }
  const area = (value: string[], on: (v: string[]) => void, placeholder: string) => <PatternList value={value} onChange={on} placeholder={placeholder} />;
  const block = (title: string, enabled: boolean, set: (v: boolean) => void, children: React.ReactNode) => (
    <fieldset style={{ border: '1px solid var(--line)', borderRadius: 12, padding: 14, margin: 0, opacity: enabled ? 1 : 0.7 }}>
      <legend style={{ padding: '0 6px' }}><label className="check"><input type="checkbox" checked={enabled} onChange={e => set(e.target.checked)} /><b>{title}</b></label></legend>
      {enabled && <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>{children}</div>}
    </fieldset>);

  return (
    <Modal title="Log access policy" onClose={onClose} wide>
      <form onSubmit={save} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="seg" style={{ flexWrap: 'wrap', alignSelf: 'flex-start' }}>{PRESETS.map(x => <button type="button" key={x.label} title={x.hint} onClick={() => setP({ ...x.policy, ssh: x.label === 'Nothing' ? { enabled: false, history: false } : p.ssh })}>{x.label}</button>)}</div>
        {block('SSH activity', p.ssh?.enabled !== false, v => setP({ ...p, ssh: { enabled: v, history: p.ssh?.history !== false } }), <>
          <p className="muted sm" style={{ margin: 0 }}>Who is logged in over SSH, from which address, and past logins and logouts.</p>
          <label className="check"><input type="checkbox" checked={p.ssh?.history !== false} onChange={e => setP({ ...p, ssh: { enabled: true, history: e.target.checked } })} />Also show the shell command history of the server&apos;s users <span className="muted sm">(recognisable secrets are masked on the server)</span></label></>)}
        {block('Docker containers', p.docker.enabled, v => setP({ ...p, docker: { ...p.docker, enabled: v } }), <>
          <label className="field">Allowed container names <small>one pattern per line; * = any. Example: web-*</small>{area(p.docker.include, v => setP({ ...p, docker: { ...p.docker, include: v } }), '*')}</label>
          <label className="field">Never allow <small>patterns that always win. Example: *-secrets</small>{area(p.docker.exclude, v => setP({ ...p, docker: { ...p.docker, exclude: v } }), '')}</label></>)}
        {block('System journal', p.journal.enabled, v => setP({ ...p, journal: { ...p.journal, enabled: v } }), <>
          <label className="field">Allowed units <small>* also allows reading the whole journal. Example: nginx*, ssh.service</small>{area(p.journal.units, v => setP({ ...p, journal: { ...p.journal, units: v } }), '*')}</label></>)}
        {block('Log files', p.files.enabled, v => setP({ ...p, files: { ...p.files, enabled: v } }), (
          <>
            <div className="seg" style={{ alignSelf: 'flex-start' }}>
              <button type="button" className={p.files.mode === 'all' ? 'on' : ''} onClick={() => setP({ ...p, files: { ...p.files, mode: 'all' } })}>All readable files</button>
              <button type="button" className={p.files.mode === 'selected' ? 'on' : ''} onClick={() => setP({ ...p, files: { ...p.files, mode: 'selected' } })}>Only selected types</button>
            </div>
            {p.files.mode === 'selected' && (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(250px,1fr))', gap: 8 }}>
                  {catalog.map(c => (
                    <label key={c.id} className="check" style={{ alignItems: 'flex-start', padding: '8px 10px', border: '1px solid var(--line-2)', borderRadius: 9, background: p.files.categories.includes(c.id) ? 'var(--surface-2)' : 'transparent' }}>
                      <input type="checkbox" checked={p.files.categories.includes(c.id)} onChange={() => toggleCat(c.id)} />
                      <span><b>{c.label}</b><br /><span className="muted sm">{c.hint}</span></span>
                    </label>
                  ))}
                </div>
                <label className="field">Extra file patterns <small>absolute paths, one per line. Example: /srv/app/logs/*.log</small>{area(p.files.custom, v => setP({ ...p, files: { ...p.files, custom: v } }), '')}</label>
              </>
            )}
          </>
        ))}
        <p className="muted sm">The control plane blocks anything outside this policy and the agent enforces it too, so a compromised control plane cannot make the agent expose more. Changes take effect at the agent&apos;s next report (seconds).</p>
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}><button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save policy'}</button></div>
      </form>
    </Modal>
  );
}

/** Admin shortcut on the Logs page: choose which kinds of logs this server's agent exposes (so fewer files are listed and scanned). */
export function LogPolicyButton({ serverId, onSaved }: { serverId: number; onSaved: () => void }) {
  const { toast } = useApp();
  const [initial, setInitial] = useState<Policy | null>(null);
  const [busy, setBusy] = useState(false);
  async function open() {
    setBusy(true);
    try { setInitial((await api<{ policy: Policy }>(`/servers/${serverId}/log-policy`)).policy); } catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  return (
    <>
      <button className="lgx-btn" onClick={() => void open()} disabled={busy} title="Admins: choose which kinds of logs this server exposes"><Icon name="shield" size={14} /><span>Access</span></button>
      {initial && <PolicyEditor serverId={serverId} initial={initial} onClose={() => setInitial(null)} onSaved={() => { setInitial(null); toast('Saved. The agent applies it at its next report (within a minute).'); onSaved(); }} />}
    </>
  );
}
