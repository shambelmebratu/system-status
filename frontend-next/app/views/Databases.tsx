'use client';

import { FormEvent, PointerEvent as RPointerEvent, WheelEvent as RWheelEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Empty, Field, Icon, Modal } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { timeAgo } from '../lib/format';

/* ---------------------------------------------------------------- types */
type Conn = { id: number; name: string; engine: 'postgresql' | 'mysql' | 'mongodb'; host: string; port: number; database: string; username: string; has_password: boolean; ssl_mode: string; auth_source: string;
  schemas: string[]; created_by: string | null; last_ok_at: string | null; last_error: string | null; server_version: string | null };
type Col = { name: string; type: string; nullable: boolean; default: string | null; pk: boolean; fk: boolean; comment: string; sensitive: boolean };
type Tbl = { key: string; schema: string; name: string; kind: 'table' | 'view' | 'collection'; rows_estimate: number | null; size_bytes: number | null; comment: string; columns: Col[] };
type Rel = { name: string; from: string; from_columns: string[]; to: string; to_columns: string[]; inferred?: boolean };
type Schema = { tables: Tbl[]; relations: Rel[]; server_version: string | null; read_at: string };
type Pick = { table: string; columns: string[] };
type Saved = { id: number; name: string; selection: Pick[]; sample_rows: number; created_by: string | null; updated_at: string };
type ColStat = { name: string; type: string; nullable: boolean; pk: boolean; sensitive: boolean; comment: string; non_null?: number; nulls?: number; null_pct?: number; distinct?: number;
  unique?: boolean; min?: unknown; max?: unknown; avg?: unknown; avg_length?: number | null; top?: { value: unknown; count: number; pct: number }[]; error?: string };
type RelText = { from: string; to: string; from_columns: string[]; to_columns: string[]; optional: boolean; text: string };
type Section = { table: string; schema: string; name: string; kind: string; comment: string; size_bytes: number | null; summary: string; quality: string[]; references: RelText[]; referenced_by: RelText[];
  primary_key: string[]; profile: { rows: number; rows_exact: boolean; columns: ColStat[]; sample: unknown[][]; notes: string[]; seconds: number } };
type Report = { title: string; engine: string; generated_at: string; overview: string; issues: number; relations: RelText[]; tables: Section[]; database: { name: string; engine: string; database: string; server_version: string | null } };

const ENGINE_LABEL = { postgresql: 'PostgreSQL', mysql: 'MySQL / MariaDB', mongodb: 'MongoDB' } as const;
const DEFAULT_PORT = { postgresql: 5432, mysql: 3306, mongodb: 27017 } as const;
/** Words for one database family: tables and rows, or collections and documents. */
const words = (engine: string) => (engine === 'mongodb' ? { table: 'collection', tables: 'Collections', row: 'document', rows: 'documents', col: 'field', cols: 'Fields' } : { table: 'table', tables: 'Tables', row: 'row', rows: 'rows', col: 'column', cols: 'Columns' });
const bytes = (n: number | null) => (n == null ? '–' : n < 1024 ** 2 ? `${Math.max(1, Math.round(n / 1024))} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`);
const num = (n: number | null | undefined) => (n == null ? '–' : n.toLocaleString());
const shown = (v: unknown) => (v == null ? '–' : String(v));

/* ---------------------------------------------------------------- page */
export function Databases() {
  const { route, go } = useApp();
  const list = usePoll(() => api<Conn[]>('/databases'), [], 60000);
  const [editing, setEditing] = useState<Conn | 'new' | null>(null);
  const id = Number(route[1]);
  const current = list.value?.find(c => c.id === id);
  if (current) return <DatabaseDetail conn={current} onEdit={() => setEditing(current)} reload={list.reload} editing={editing} closeEdit={() => setEditing(null)} />;
  return (
    <>
      <div className="topbar"><div><h1>Databases</h1><p className="muted sm">See how your tables relate and generate readable data reports. Read-only: nothing is ever changed.</p></div><span className="grow" />
        <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />Connect a database</button></div>
      {list.error && <div className="err">{list.error}</div>}
      {list.value && list.value.length === 0 && <div className="card"><Empty title="No databases connected" action={<button className="btn primary" onClick={() => setEditing('new')}>Connect a database</button>}>
        PostgreSQL, MySQL / MariaDB and MongoDB. Use a database user that can only read: SM-Watch also only ever reads, and stops any query after 15 seconds.</Empty></div>}
      <div className="tilegrid">
        {(list.value ?? []).map(c => (
          <div key={c.id} className="card tile db-tile" onClick={() => go(`databases/${c.id}`)}>
            <div className="tile-top"><span className="db-ico"><Icon name="database" size={18} /></span><div className="grow"><div className="name">{c.name}</div><small className="muted">{ENGINE_LABEL[c.engine]}{c.server_version ? ` ${c.server_version}` : ''}</small></div>
              <span className={`kstatus ${c.last_error ? 'bad' : c.last_ok_at ? 'ok' : 'muted'}`}><i />{c.last_error ? 'Error' : c.last_ok_at ? 'Connected' : 'Not used yet'}</span></div>
            <div className="mono sm muted trunc">{c.username}@{c.host}:{c.port}/{c.database}</div>
            {c.last_error ? <div className="sm bad trunc" title={c.last_error}>{c.last_error}</div> : <div className="sm muted">{c.last_ok_at ? `read ${timeAgo(c.last_ok_at)}` : ''}</div>}
          </div>))}
      </div>
      {editing && <ConnectionForm existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={async c => { setEditing(null); await list.reload(); if (c) go(`databases/${c.id}`); }} />}
    </>
  );
}

function ConnectionForm({ existing, onClose, onSaved }: { existing?: Conn; onClose: () => void; onSaved: (c?: Conn) => void }) {
  const { toast, confirm, go } = useApp();
  const [f, setF] = useState({ name: existing?.name ?? '', engine: existing?.engine ?? 'postgresql', host: existing?.host ?? '', port: existing ? String(existing.port) : '', database: existing?.database ?? '',
    username: existing?.username ?? '', password: '', ssl_mode: existing?.ssl_mode ?? 'prefer', schemas: (existing?.schemas ?? []).join(', '), auth_source: existing?.auth_source ?? '' });
  const [busy, setBusy] = useState(''); const [error, setError] = useState(''); const [tested, setTested] = useState('');
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => { setF({ ...f, [k]: e.target.value }); setTested(''); };
  const body = () => ({ ...f, port: f.port ? Number(f.port) : null, schemas: f.schemas.split(/[\s,]+/).filter(Boolean) });
  async function test() {
    setBusy('test'); setError(''); setTested('');
    try { const r = await post<{ version: string; tables: number; relations: number; ms: number }>('/databases/test', { ...body(), id: existing?.id }); setTested(`Connected in ${r.ms} ms · version ${r.version} · ${r.tables} tables, ${r.relations} relationships`); }
    catch (e) { setError((e as Error).message); } finally { setBusy(''); }
  }
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy('save'); setError('');
    try { const c = existing ? await put<Conn>(`/databases/${existing.id}`, body()) : await post<Conn>('/databases', body()); toast(existing ? 'Connection updated' : 'Database connected'); onSaved(c); }
    catch (e2) { setError((e2 as Error).message); } finally { setBusy(''); }
  }
  async function remove() {
    if (!existing || !(await confirm(`Remove ${existing.name}?\n\nOnly the connection and its saved reports are removed from SM-Watch. The database itself is not touched.`))) return;
    try { await del(`/databases/${existing.id}`); toast('Connection removed'); go('databases'); onSaved(); } catch (e) { setError((e as Error).message); }
  }
  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'Connect a database'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="method" role="radiogroup" aria-label="Engine">{(['postgresql', 'mysql', 'mongodb'] as const).map(e => <button type="button" key={e} role="radio" aria-checked={f.engine === e} className={f.engine === e ? 'on' : ''} onClick={() => { setF({ ...f, engine: e }); setTested(''); }}><b>{ENGINE_LABEL[e]}</b><span>Default port {DEFAULT_PORT[e]}{e === 'mongodb' ? ' · fields and relations are inferred' : ''}</span></button>)}</div>
        <div className="form-grid">
          <Field label="Name"><input value={f.name} onChange={set('name')} placeholder="ERP production" required maxLength={100} autoFocus /></Field>
          <Field label="Host" hint="Name or IP the SM-Watch server can reach (private / VPN addresses are fine)"><input value={f.host} onChange={set('host')} placeholder="10.0.0.12" required /></Field>
          <Field label="Port"><input type="number" min={1} max={65535} value={f.port} onChange={set('port')} placeholder={String(DEFAULT_PORT[f.engine])} /></Field>
          <Field label="Database"><input value={f.database} onChange={set('database')} placeholder="erp" required={f.engine !== 'mysql'} /></Field>
          <Field label="User" hint="Ideally a user that can only read"><input value={f.username} onChange={set('username')} placeholder="report_ro" required autoComplete="off" /></Field>
          <Field label="Password" hint={existing?.has_password ? 'Leave empty to keep the stored password' : 'Stored encrypted; never shown again'}><input type="password" value={f.password} onChange={set('password')} autoComplete="new-password" placeholder={existing?.has_password ? '••••••••' : ''} /></Field>
          <Field label="TLS"><select value={f.ssl_mode} onChange={set('ssl_mode')}><option value="prefer">{f.engine === 'mongodb' ? 'No TLS (private network only)' : 'Use TLS if the server offers it'}</option><option value="require">Require TLS</option><option value="verify-full">Require TLS and a trusted certificate</option><option value="disable">No TLS (private network only)</option></select></Field>
          {f.engine === 'mongodb'
            ? <Field label="Authentication database" hint="Where the user was created (authSource). Empty = the database above; often admin"><input value={f.auth_source} onChange={set('auth_source')} placeholder="admin" /></Field>
            : <Field label={f.engine === 'postgresql' ? 'Schemas' : 'Databases (schemas)'} hint={f.engine === 'postgresql' ? 'Comma-separated. Empty = every non-system schema' : 'Comma-separated. Empty = the database above'}><input value={f.schemas} onChange={set('schemas')} placeholder={f.engine === 'postgresql' ? 'public, billing' : ''} /></Field>}
        </div>
        <details className="db-howto"><summary>Create a read-only user (recommended)</summary>
          <pre className="codebox">{f.engine === 'mongodb'
            ? `use ${f.database || 'erp'}\ndb.createUser({ user: "report_ro", pwd: "…", roles: [{ role: "read", db: "${f.database || 'erp'}" }] })`
            : f.engine === 'postgresql'
            ? `CREATE ROLE report_ro LOGIN PASSWORD '…';\nGRANT CONNECT ON DATABASE ${f.database || 'erp'} TO report_ro;\nGRANT USAGE ON SCHEMA public TO report_ro;\nGRANT SELECT ON ALL TABLES IN SCHEMA public TO report_ro;\nALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO report_ro;`
            : `CREATE USER 'report_ro'@'%' IDENTIFIED BY '…';\nGRANT SELECT, SHOW VIEW ON ${f.database || 'erp'}.* TO 'report_ro'@'%';`}</pre></details>
        {tested && <div className="ok-box"><Icon name="check" size={15} /> {tested}</div>}
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'space-between', flexWrap: 'wrap' }}>
          {existing ? <button type="button" className="btn danger" onClick={remove}>Remove</button> : <span />}
          <span style={{ display: 'flex', gap: 10 }}><button type="button" className="btn" onClick={test} disabled={!!busy || !f.host || !f.username}>{busy === 'test' ? 'Testing…' : 'Test connection'}</button>
            <button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!!busy}>{busy === 'save' ? 'Saving…' : 'Save'}</button></span>
        </div>
      </form>
    </Modal>
  );
}

/* ---------------------------------------------------------------- one database */
function DatabaseDetail({ conn, onEdit, reload, editing, closeEdit }: { conn: Conn; onEdit: () => void; reload: () => Promise<void>; editing: Conn | 'new' | null; closeEdit: () => void }) {
  const { go } = useApp();
  const [tab, setTab] = useState<'graph' | 'tree' | 'report' | 'saved'>('graph');
  const [schema, setSchema] = useState<Schema | null>(null);
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  const [picks, setPicks] = useState<Record<string, string[] | null>>({});      // table -> chosen columns (null = all)
  const [report, setReport] = useState<Report | null>(null);
  const load = useCallback(async (refresh = false) => {
    setBusy(true); setError('');
    try { setSchema(await api<Schema>(`/databases/${conn.id}/schema${refresh ? '?refresh=1' : ''}`)); void reload(); }
    catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  }, [conn.id, reload]);
  useEffect(() => { void load(); }, [load]);
  const addToReport = (key: string) => { setPicks(p => ({ ...p, [key]: p[key] ?? null })); setTab('report'); };
  const tables = schema?.tables ?? [];
  const w = words(conn.engine);
  return (
    <>
      <div className="topbar">
        <button className="btn ghost sm" onClick={() => go('databases')}><Icon name="back" size={15} />Databases</button>
        <span className="db-ico"><Icon name="database" size={18} /></span><div style={{ minWidth: 0, flex: '1 1 200px' }}><h1 className="trunc">{conn.name}</h1><div className="muted sm mono trunc" title={`${conn.username}@${conn.host}:${conn.port}/${conn.database}`}>{ENGINE_LABEL[conn.engine]} {schema?.server_version ?? conn.server_version ?? ''} · {conn.username}@{conn.host}:{conn.port}/{conn.database}</div></div>
        <button className="btn sm" onClick={() => void load(true)} disabled={busy}><Icon name="refresh" size={14} />{busy ? 'Reading…' : 'Re-read schema'}</button>
        <button className="btn sm" onClick={onEdit}>Edit</button>
      </div>
      {schema && <div className="ssh-stats" style={{ marginBottom: 14 }}>
        <div className="card ssh-stat"><small>{w.tables}</small><b>{tables.filter(t => t.kind !== 'view').length}</b><span className="muted sm">{tables.filter(t => t.kind === 'view').length} views</span></div>
        <div className="card ssh-stat"><small>Relationships</small><b>{schema.relations.length}</b><span className="muted sm">{conn.engine === 'mongodb' ? `${schema.relations.filter(r => r.inferred).length} inferred from matching ids` : 'foreign keys'}</span></div>
        <div className="card ssh-stat"><small>{w.rows[0].toUpperCase() + w.rows.slice(1)} (estimate)</small><b className="sm-b">{num(tables.reduce((a, t) => a + (t.rows_estimate ?? 0), 0))}</b><span className="muted sm">from the database&apos;s statistics</span></div>
        <div className="card ssh-stat"><small>Size</small><b className="sm-b">{tables.some(t => t.size_bytes != null) ? bytes(tables.reduce((a, t) => a + (t.size_bytes ?? 0), 0)) : '–'}</b><span className="muted sm">{w.table}s and indexes</span></div>
      </div>}
      <div className="ktabs" role="tablist">{([['graph', 'Relationships', 'overview'], ['tree', w.tables, 'logs'], ['report', `Report builder${Object.keys(picks).length ? ` (${Object.keys(picks).length})` : ''}`, 'zap'], ['saved', 'Saved reports', 'star']] as const).map(([id, label, icon]) =>
        <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}><Icon name={icon} size={15} />{label}</button>)}</div>
      {error && <div className="err" style={{ marginBottom: 12 }}>{error}</div>}
      {!schema ? (!error && <div className="card"><p className="muted"><span className="spinner" /> Reading the schema…</p></div>) : <>
        {tab === 'graph' && <SchemaGraph schema={schema} onAdd={addToReport} engine={conn.engine} />}
        {tab === 'tree' && <SchemaTree schema={schema} onAdd={addToReport} engine={conn.engine} />}
        {tab === 'report' && <ReportBuilder conn={conn} schema={schema} picks={picks} setPicks={setPicks} onReport={setReport} />}
        {tab === 'saved' && <SavedReports conn={conn} onOpen={(s) => { setPicks(Object.fromEntries(s.selection.map(p => [p.table, p.columns.length ? p.columns : null]))); setTab('report'); }} onReport={setReport} />}
      </>}
      {report && <ReportView report={report} onClose={() => setReport(null)} />}
      {editing && editing !== 'new' && <ConnectionForm existing={editing} onClose={closeEdit} onSaved={async () => { closeEdit(); await reload(); void load(true); }} />}
    </>
  );
}

/* ---------------------------------------------------------------- relationship graph (nodes + edges, pan / zoom / drag) */
const NODE_W = 230, HEAD = 30, ROW = 20, MAX_ROWS = 8;
type Pos = { x: number; y: number };
function nodeRows(t: Tbl) { const keys = t.columns.filter(c => c.pk || c.fk); const rest = t.columns.filter(c => !c.pk && !c.fk); const show = [...keys, ...rest].slice(0, MAX_ROWS); return { show, more: t.columns.length - show.length }; }
const nodeH = (t: Tbl) => { const r = nodeRows(t); return HEAD + r.show.length * ROW + (r.more ? ROW : 0) + 6; };

/** A small force layout: connected tables pull together, everything else pushes apart. Deterministic (same schema, same picture). */
function layout(tables: Tbl[], rels: Rel[]): Record<string, Pos> {
  const n = tables.length, idx = new Map(tables.map((t, i) => [t.key, i]));
  const deg = new Array(n).fill(0); rels.forEach(r => { const a = idx.get(r.from), b = idx.get(r.to); if (a != null && b != null) { deg[a]++; deg[b]++; } });
  const order = tables.map((_, i) => i).sort((a, b) => deg[b] - deg[a]);
  const pos = new Array(n).fill(0).map(() => ({ x: 0, y: 0 }));
  order.forEach((i, k) => { const r = 140 * Math.sqrt(k + 1), a = k * 2.399; pos[i] = { x: r * Math.cos(a), y: r * Math.sin(a) }; });
  const edges = rels.map(r => [idx.get(r.from), idx.get(r.to)]).filter((e): e is [number, number] => e[0] != null && e[1] != null && e[0] !== e[1]);
  const iterations = n > 150 ? 120 : 320;
  for (let it = 0; it < iterations; it++) {
    const cool = 1 - it / iterations, disp = pos.map(() => ({ x: 0, y: 0 }));
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
      let dx = pos[i].x - pos[j].x, dy = pos[i].y - pos[j].y; const d2 = dx * dx + dy * dy || 0.01, d = Math.sqrt(d2);
      const f = 90000 / d2; dx /= d; dy /= d; disp[i].x += dx * f; disp[i].y += dy * f; disp[j].x -= dx * f; disp[j].y -= dy * f;
    }
    for (const [a, b] of edges) { const dx = pos[a].x - pos[b].x, dy = pos[a].y - pos[b].y, d = Math.sqrt(dx * dx + dy * dy) || 0.01, f = (d - 320) * 0.06; disp[a].x -= (dx / d) * f; disp[a].y -= (dy / d) * f; disp[b].x += (dx / d) * f; disp[b].y += (dy / d) * f; }
    for (let i = 0; i < n; i++) { disp[i].x -= pos[i].x * 0.01; disp[i].y -= pos[i].y * 0.01; const l = Math.hypot(disp[i].x, disp[i].y), cap = 40 * cool + 2; if (l > cap) { disp[i].x *= cap / l; disp[i].y *= cap / l; } pos[i].x += disp[i].x; pos[i].y += disp[i].y; }
  }
  return Object.fromEntries(tables.map((t, i) => [t.key, { x: pos[i].x - NODE_W / 2, y: pos[i].y - nodeH(t) / 2 }]));
}

function SchemaGraph({ schema, onAdd, engine }: { schema: Schema; onAdd: (key: string) => void; engine: string }) {
  const w = words(engine);
  const [q, setQ] = useState('');
  const [focus, setFocus] = useState<string | null>(null);
  const [depth, setDepth] = useState(1);
  const [showViews, setShowViews] = useState(false);
  const big = schema.tables.length > 80;
  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    schema.relations.forEach(r => { (m.get(r.from) ?? m.set(r.from, new Set()).get(r.from)!).add(r.to); (m.get(r.to) ?? m.set(r.to, new Set()).get(r.to)!).add(r.from); });
    return m;
  }, [schema]);
  // Which tables are drawn: everything for small schemas; around the focused table for big ones (or when a table is focused).
  const visible = useMemo(() => {
    let keys = new Set(schema.tables.filter(t => showViews || t.kind !== 'view').map(t => t.key));
    if (focus) { const seen = new Set([focus]); let frontier = [focus]; for (let d = 0; d < depth; d++) { const next: string[] = []; frontier.forEach(k => neighbours.get(k)?.forEach(n => { if (!seen.has(n)) { seen.add(n); next.push(n); } })); frontier = next; } keys = new Set([...seen].filter(k => keys.has(k) || k === focus)); }
    else if (big) keys = new Set([...keys].filter(k => neighbours.has(k)).slice(0, 80));
    return schema.tables.filter(t => keys.has(t.key));
  }, [schema, focus, depth, neighbours, big, showViews]);
  const rels = useMemo(() => { const v = new Set(visible.map(t => t.key)); return schema.relations.filter(r => v.has(r.from) && v.has(r.to)); }, [visible, schema]);
  const initial = useMemo(() => layout(visible, rels), [visible, rels]);
  const [pos, setPos] = useState(initial);
  useEffect(() => setPos(initial), [initial]);
  const [view, setView] = useState({ x: 0, y: 0, k: 0.8 });
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ kind: 'pan' | 'node'; key?: string; sx: number; sy: number; ox: number; oy: number; moved: boolean } | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const fit = useCallback(() => {
    const el = box.current; const ps = Object.entries(pos); if (!el || !ps.length) return;
    const tb = new Map(visible.map(t => [t.key, t]));
    const xs = ps.map(([, p]) => p.x), ys = ps.map(([, p]) => p.y), x2 = ps.map(([, p]) => p.x + NODE_W), y2 = ps.map(([k, p]) => p.y + nodeH(tb.get(k)!));
    const minX = Math.min(...xs), minY = Math.min(...ys), w = Math.max(...x2) - minX, h = Math.max(...y2) - minY;
    const k = Math.min(1.2, Math.max(0.15, Math.min(el.clientWidth / (w + 80), el.clientHeight / (h + 80))));
    setView({ k, x: (el.clientWidth - w * k) / 2 - minX * k, y: (el.clientHeight - h * k) / 2 - minY * k });
  }, [pos, visible]);
  useEffect(() => { fit(); }, [initial]); // eslint-disable-line react-hooks/exhaustive-deps
  const matches = q.trim() ? schema.tables.filter(t => t.key.toLowerCase().includes(q.trim().toLowerCase())).slice(0, 8) : [];
  const tb = new Map(visible.map(t => [t.key, t]));
  const hi = selected ? new Set([selected, ...(neighbours.get(selected) ?? [])]) : null;

  const onDown = (e: RPointerEvent, key?: string) => { e.stopPropagation(); (e.currentTarget as Element).setPointerCapture(e.pointerId); const p = key ? pos[key] : view; drag.current = { kind: key ? 'node' : 'pan', key, sx: e.clientX, sy: e.clientY, ox: p.x, oy: p.y, moved: false }; };
  const onMove = (e: RPointerEvent) => { const d = drag.current; if (!d) return; const dx = e.clientX - d.sx, dy = e.clientY - d.sy; if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
    if (d.kind === 'pan') setView(v => ({ ...v, x: d.ox + dx, y: d.oy + dy })); else setPos(p => ({ ...p, [d.key!]: { x: d.ox + dx / view.k, y: d.oy + dy / view.k } })); };
  const onUp = () => { const d = drag.current; drag.current = null; if (d && !d.moved) setSelected(d.kind === 'node' ? d.key! : null); };
  const onWheel = (e: RWheelEvent) => { const el = box.current!; const r = el.getBoundingClientRect(); const mx = e.clientX - r.left, my = e.clientY - r.top; const k = Math.min(2.5, Math.max(0.1, view.k * (e.deltaY < 0 ? 1.12 : 0.89)));
    setView(v => ({ k, x: mx - ((mx - v.x) / v.k) * k, y: my - ((my - v.y) / v.k) * k })); };
  const zoom = (f: number) => { const el = box.current!; const mx = el.clientWidth / 2, my = el.clientHeight / 2; setView(v => { const k = Math.min(2.5, Math.max(0.1, v.k * f)); return { k, x: mx - ((mx - v.x) / v.k) * k, y: my - ((my - v.y) / v.k) * k }; }); };
  const sel = selected ? schema.tables.find(t => t.key === selected) : null;

  return (
    <div className="db-graph-wrap">
      <div className="filterbar">
        <div className="db-search"><label className="lg-field"><Icon name="logs" size={15} /><input value={q} onChange={e => setQ(e.target.value)} placeholder={`Find a ${w.table}…`} aria-label="Find" /></label>
          {matches.length > 0 && <div className="db-matches">{matches.map(t => <button key={t.key} type="button" onClick={() => { setFocus(t.key); setSelected(t.key); setQ(''); }}>{t.name}<small>{t.schema}</small></button>)}</div>}</div>
        {focus && <span className="lg-chip">around {focus.split('.').pop()} <button type="button" className="lg-link" onClick={() => setFocus(null)}>show all</button></span>}
        {focus && <div className="seg">{[1, 2, 3].map(d => <button key={d} className={depth === d ? 'on' : ''} onClick={() => setDepth(d)}>{d} step{d > 1 ? 's' : ''}</button>)}</div>}
        <label className="check"><input type="checkbox" checked={showViews} onChange={e => setShowViews(e.target.checked)} />Views</label>
        <span className="grow" /><span className="muted sm">{visible.length} {w.table}s · {rels.length} links{big && !focus ? ` (connected ${w.table}s only: find one to focus)` : ''}</span>
      </div>
      <div className="db-graph-row">
        <div className="db-graph card flush" ref={box} onPointerDown={e => onDown(e)} onPointerMove={onMove} onPointerUp={onUp} onWheel={onWheel}>
          <div className="db-zoom"><button onClick={() => zoom(1.25)} aria-label="Zoom in">+</button><button onClick={() => zoom(0.8)} aria-label="Zoom out">−</button><button onClick={fit} aria-label="Fit">⤢</button></div>
          {visible.length === 0 ? <div style={{ padding: 30 }}><Empty title="Nothing to draw">No tables in the chosen schemas.</Empty></div> : (
            <svg width="100%" height="100%">
              <defs><marker id="db-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="var(--accent)" /></marker></defs>
              <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
                {rels.map((r, i) => {
                  const a = pos[r.from], b = pos[r.to], ta = tb.get(r.from), tbb = tb.get(r.to); if (!a || !b || !ta || !tbb) return null;
                  const row = nodeRows(ta).show.findIndex(c => c.name === r.from_columns[0]);
                  const ay = a.y + (row >= 0 ? HEAD + row * ROW + ROW / 2 : HEAD / 2), by = b.y + HEAD / 2;
                  const leftToRight = a.x + NODE_W / 2 < b.x + NODE_W / 2;
                  const ax = leftToRight ? a.x + NODE_W : a.x, bx = leftToRight ? b.x : b.x + NODE_W, c = Math.max(60, Math.abs(bx - ax) / 2) * (leftToRight ? 1 : -1);
                  const on = !hi || (hi.has(r.from) && hi.has(r.to) && (r.from === selected || r.to === selected));
                  return <path key={i} d={`M${ax},${ay} C${ax + c},${ay} ${bx - c},${by} ${bx},${by}`} className={`db-edge ${on ? '' : 'dim'} ${r.inferred ? 'inferred' : ''}`} markerEnd="url(#db-arrow)"><title>{`${r.from}.${r.from_columns.join(',')} → ${r.to}.${r.to_columns.join(',')}`}</title></path>;
                })}
                {visible.map(t => { const p = pos[t.key]; if (!p) return null; const { show, more } = nodeRows(t); const h = nodeH(t); const dim = hi && !hi.has(t.key); return (
                  <g key={t.key} transform={`translate(${p.x},${p.y})`} className={`db-node ${selected === t.key ? 'sel' : ''} ${dim ? 'dim' : ''} ${t.kind}`} onPointerDown={e => onDown(e, t.key)}>
                    <rect width={NODE_W} height={h} rx={10} className="db-node-box" />
                    <rect width={NODE_W} height={HEAD} rx={10} className="db-node-head" /><rect y={HEAD - 10} width={NODE_W} height={10} className="db-node-head" />
                    <text x={12} y={20} className="db-node-title">{t.name.length > 24 ? `${t.name.slice(0, 23)}…` : t.name}</text>
                    <text x={NODE_W - 10} y={20} textAnchor="end" className="db-node-count">{t.rows_estimate != null ? `${t.rows_estimate >= 1e6 ? `${(t.rows_estimate / 1e6).toFixed(1)}M` : t.rows_estimate >= 1e3 ? `${(t.rows_estimate / 1e3).toFixed(1)}k` : t.rows_estimate}` : ''}</text>
                    {show.map((c, i) => <g key={c.name} transform={`translate(0,${HEAD + i * ROW})`}>
                      <text x={12} y={14} className={`db-col ${c.pk ? 'pk' : c.fk ? 'fk' : ''}`}>{c.pk ? '🔑 ' : c.fk ? '↗ ' : ''}{c.name.length > 20 ? `${c.name.slice(0, 19)}…` : c.name}</text>
                      <text x={NODE_W - 10} y={14} textAnchor="end" className="db-type">{c.type.length > 14 ? `${c.type.slice(0, 13)}…` : c.type}</text></g>)}
                    {more > 0 && <text x={12} y={HEAD + show.length * ROW + 14} className="db-type">+ {more} more {w.col}{more > 1 ? 's' : ''}</text>}
                  </g>); })}
              </g>
            </svg>)}
        </div>
        {sel && <TableCard t={sel} schema={schema} engine={engine} onAdd={onAdd} onFocus={() => setFocus(sel.key)} onPick={k => { setSelected(k); if (!tb.has(k)) setFocus(k); }} onClose={() => setSelected(null)} />}
      </div>
      <p className="muted sm">Drag the background to move, scroll to zoom, drag a {w.table} to rearrange. Click one for its {w.col}s and relationships. 🔑 {engine === 'mongodb' ? '_id' : 'primary key'} · ↗ refers to another {w.table}{engine === 'mongodb' ? ' · dashed = inferred from matching ids' : ''}.</p>
    </div>
  );
}

function TableCard({ t, schema, engine, onAdd, onFocus, onPick, onClose }: { t: Tbl; schema: Schema; engine: string; onAdd: (k: string) => void; onFocus?: () => void; onPick: (k: string) => void; onClose?: () => void }) {
  const w = words(engine);
  const out = schema.relations.filter(r => r.from === t.key), inc = schema.relations.filter(r => r.to === t.key);
  return (
    <aside className="card db-side">
      <div className="card-head"><div style={{ minWidth: 0 }}><div className="muted sm">{t.kind === 'view' ? 'View' : t.kind === 'collection' ? 'Collection' : 'Table'} · {t.schema}</div><h2 className="trunc" style={{ textTransform: 'none', letterSpacing: 0 }}>{t.name}</h2></div><span className="grow" />{onClose && <button className="btn ghost sm" onClick={onClose} aria-label="Close"><Icon name="x" /></button>}</div>
      {t.comment && <p className="sm" style={{ marginTop: 0 }}>{t.comment}</p>}
      <div className="facts"><div><small>{w.rows} (estimate)</small><b>{num(t.rows_estimate)}</b></div><div><small>Size</small><b>{bytes(t.size_bytes)}</b></div></div>
      <div style={{ display: 'flex', gap: 8, margin: '10px 0' }}><button className="btn sm primary" onClick={() => onAdd(t.key)}><Icon name="plus" size={13} />Add to report</button>{onFocus && <button className="btn sm" onClick={onFocus}>Focus graph here</button>}</div>
      {out.length > 0 && <><h3 className="drawer-h">Refers to</h3>{out.map(r => <button key={r.name} className="rel-row" onClick={() => onPick(r.to)}><b>{r.to.split('.').pop()}</b><span className="muted sm">many → one</span><span className="mono sm">{r.from_columns.join(', ')} → {r.to_columns.join(', ')}{r.inferred ? ' · inferred' : ''}</span></button>)}</>}
      {inc.length > 0 && <><h3 className="drawer-h">Referred to by</h3>{inc.map(r => <button key={r.name + r.from} className="rel-row" onClick={() => onPick(r.from)}><b>{r.from.split('.').pop()}</b><span className="muted sm">one → many</span><span className="mono sm">{r.from.split('.').pop()}.{r.from_columns.join(', ')}</span></button>)}</>}
      <h3 className="drawer-h">{w.cols} <span className="tag">{t.columns.length}</span></h3>
      <table className="tbl db-cols"><tbody>{t.columns.map(c => <tr key={c.name} title={c.comment}><td><b className={c.pk ? 'good' : ''}>{c.pk ? '🔑 ' : c.fk ? '↗ ' : ''}{c.name}</b>{c.sensitive && <span className="tag" title="Values are never shown in reports">masked</span>}</td><td className="mono sm muted">{c.type}{c.nullable ? '' : engine === 'mongodb' ? ' · always present' : ' · required'}{c.comment && engine === 'mongodb' ? <div>{c.comment}</div> : null}</td></tr>)}</tbody></table>
    </aside>
  );
}

/* ---------------------------------------------------------------- nested tree */
function SchemaTree({ schema, onAdd, engine }: { schema: Schema; onAdd: (k: string) => void; engine: string }) {
  const w = words(engine);
  const [q, setQ] = useState(''); const [open, setOpen] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const needle = q.trim().toLowerCase();
  const rows = schema.tables.filter(t => !needle || t.key.toLowerCase().includes(needle) || t.columns.some(c => c.name.toLowerCase().includes(needle)));
  useEffect(() => setPage(0), [needle]);
  const size = 30, pages = Math.max(1, Math.ceil(rows.length / size));
  const bySchema = new Map<string, Tbl[]>(); rows.slice(page * size, page * size + size).forEach(t => (bySchema.get(t.schema) ?? bySchema.set(t.schema, []).get(t.schema)!).push(t));
  const byKey = new Map(schema.tables.map(t => [t.key, t]));
  return (
    <div className="db-graph-row">
      <section className="card" style={{ flex: 1, minWidth: 0 }}>
        <label className="lg-field" style={{ marginBottom: 12 }}><Icon name="logs" size={15} /><input value={q} onChange={e => setQ(e.target.value)} placeholder={`Find a ${w.table} or ${w.col}…`} aria-label="Find" /></label>
        {[...bySchema.entries()].map(([s, list]) => (
          <div key={s} className="db-tree"><div className="db-tree-schema">{s}</div>
            {list.map(t => { const out = schema.relations.filter(r => r.from === t.key), inc = schema.relations.filter(r => r.to === t.key); const isOpen = open === t.key; return (
              <div key={t.key} className={`db-tree-node ${isOpen ? 'open' : ''}`}>
                <button type="button" className="db-tree-head" onClick={() => setOpen(isOpen ? null : t.key)} aria-expanded={isOpen}><span>{isOpen ? '▾' : '▸'}</span><b>{t.name}</b>{t.kind === 'view' && <span className="tag">view</span>}
                  <span className="muted sm">{t.columns.length} {w.col}s · {num(t.rows_estimate)} {w.rows}</span><span className="grow" />{out.length > 0 && <span className="tag">→ {out.length}</span>}{inc.length > 0 && <span className="tag">← {inc.length}</span>}</button>
                {isOpen && <div className="db-tree-body">
                  <ul>{t.columns.map(c => <li key={c.name}><span className={c.pk ? 'good' : ''}>{c.pk ? '🔑 ' : c.fk ? '↗ ' : '· '}{c.name}</span> <span className="mono sm muted">{c.type}</span>
                    {c.fk && out.filter(r => r.from_columns.includes(c.name)).map(r => <ul key={r.name}><li className="sm">→ <button type="button" className="lg-link" onClick={() => setOpen(r.to)}>{r.to.split('.').pop()}</button>.{r.to_columns.join(', ')} <span className="muted">({byKey.get(r.to)?.columns.length ?? '?'} {w.col}s)</span></li></ul>)}</li>)}</ul>
                  {inc.length > 0 && <><div className="muted sm" style={{ margin: '6px 0 2px' }}>Referred to by</div><ul>{inc.map(r => <li key={r.name + r.from} className="sm">← <button type="button" className="lg-link" onClick={() => setOpen(r.from)}>{r.from.split('.').pop()}</button>.{r.from_columns.join(', ')}</li>)}</ul></>}
                  <button className="btn sm primary" style={{ marginTop: 8 }} onClick={() => onAdd(t.key)}><Icon name="plus" size={13} />Add to report</button>
                </div>}
              </div>); })}
          </div>))}
        {rows.length === 0 && <p className="muted">Nothing matches.</p>}
        {pages > 1 && <nav className="pager"><span className="muted sm">{page * size + 1}–{Math.min(rows.length, page * size + size)} of {rows.length}</span><span className="grow" /><button onClick={() => setPage(page - 1)} disabled={page === 0}>‹</button><span className="sm">{page + 1} / {pages}</span><button onClick={() => setPage(page + 1)} disabled={page >= pages - 1}>›</button></nav>}
      </section>
    </div>
  );
}

/* ---------------------------------------------------------------- report builder */
function ReportBuilder({ conn, schema, picks, setPicks, onReport }: { conn: Conn; schema: Schema; picks: Record<string, string[] | null>; setPicks: (p: Record<string, string[] | null>) => void; onReport: (r: Report) => void }) {
  const { toast } = useApp();
  const [q, setQ] = useState(''); const [expand, setExpand] = useState<string | null>(null);
  const [sample, setSample] = useState(0); const [title, setTitle] = useState('');
  const [busy, setBusy] = useState(''); const [error, setError] = useState('');
  const needle = q.trim().toLowerCase();
  const list = schema.tables.filter(t => !needle || t.key.toLowerCase().includes(needle));
  const toggle = (k: string) => { const n = { ...picks }; if (k in n) delete n[k]; else n[k] = null; setPicks(n); };
  const toggleCol = (t: Tbl, c: string) => { const cur = picks[t.key] ?? t.columns.map(x => x.name); const next = cur.includes(c) ? cur.filter(x => x !== c) : t.columns.map(x => x.name).filter(x => x === c || cur.includes(x)); setPicks({ ...picks, [t.key]: next.length === t.columns.length ? null : next }); };
  const selection = Object.entries(picks).map(([table, cols]) => ({ table, columns: cols ?? [] }));
  const related = (k: string) => schema.relations.filter(r => r.from === k || r.to === k).map(r => (r.from === k ? r.to : r.from)).filter(x => !(x in picks));
  async function generate() {
    setBusy('run'); setError('');
    try { onReport(await post<Report>(`/databases/${conn.id}/report`, { selection, sample_rows: sample, title })); } catch (e) { setError((e as Error).message); } finally { setBusy(''); }
  }
  async function save() {
    const tablesNamed = selection.map(s => s.table.split('.').pop()).slice(0, 4).join(', ');
    const name = (title.trim() || `Report: ${tablesNamed}${selection.length > 4 ? ' …' : ''}`).slice(0, 120);
    setBusy('save');
    try { await post(`/databases/${conn.id}/reports`, { name, selection, sample_rows: sample }); toast('Report saved'); } catch (e) { toast((e as Error).message, true); } finally { setBusy(''); }
  }
  return (
    <div className="db-graph-row">
      <section className="card" style={{ flex: 1, minWidth: 0 }}>
        <div className="card-head"><h2>Choose {words(conn.engine).table}s and {words(conn.engine).col}s</h2><span className="grow" /><span className="muted sm">{selection.length} selected</span></div>
        <label className="lg-field" style={{ marginBottom: 10 }}><Icon name="logs" size={15} /><input value={q} onChange={e => setQ(e.target.value)} placeholder="Find a table…" aria-label="Find a table" /></label>
        <div className="db-pick-list">
          {list.slice(0, 300).map(t => { const on = t.key in picks; const cols = picks[t.key]; return (
            <div key={t.key} className={`db-pick ${on ? 'on' : ''}`}>
              <div className="db-pick-head"><label className="check"><input type="checkbox" checked={on} onChange={() => toggle(t.key)} /><b>{t.name}</b><span className="muted sm">{t.schema} · {t.columns.length} {words(conn.engine).col}s · {num(t.rows_estimate)} {words(conn.engine).rows}</span></label><span className="grow" />
                {on && <button type="button" className="lg-link sm" onClick={() => setExpand(expand === t.key ? null : t.key)}>{cols ? `${cols.length} of ${t.columns.length} ${words(conn.engine).col}s` : `all ${words(conn.engine).col}s`} ▾</button>}</div>
              {on && expand === t.key && <div className="db-pick-cols">{t.columns.map(c => <label key={c.name} className="check"><input type="checkbox" checked={!cols || cols.includes(c.name)} onChange={() => toggleCol(t, c.name)} /><span className={c.pk ? 'good' : ''}>{c.pk ? '🔑 ' : c.fk ? '↗ ' : ''}{c.name}</span><small className="muted mono">{c.type}</small>{c.sensitive && <span className="tag">masked</span>}</label>)}</div>}
              {on && related(t.key).length > 0 && <div className="sm muted" style={{ paddingLeft: 26 }}>Related: {related(t.key).slice(0, 5).map(k => <button key={k} type="button" className="lg-link" style={{ marginRight: 8 }} onClick={() => setPicks({ ...picks, [k]: null })}>+ {k.split('.').pop()}</button>)}</div>}
            </div>); })}
        </div>
      </section>
      <aside className="card db-side">
        <h2>Report</h2>
        <Field label="Title (optional)"><input value={title} onChange={e => setTitle(e.target.value)} maxLength={120} placeholder="Orders and customers" /></Field>
        <Field label="Sample rows per table" hint="Values of password, token, card and similar columns are always masked"><select value={sample} onChange={e => setSample(Number(e.target.value))}><option value={0}>None (statistics only)</option><option value={5}>5 rows</option><option value={10}>10 rows</option><option value={20}>20 rows</option></select></Field>
        <p className="muted sm">For each table: row count, size, keys, relationships in plain words, per-column completeness, distinct values, ranges and most common values, plus data-quality notes. Big tables are profiled on their first 100,000 rows.</p>
        {error && <div className="err">{error}</div>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}><button className="btn primary" onClick={generate} disabled={!selection.length || !!busy}>{busy === 'run' ? 'Generating…' : 'Generate report'}</button>
          <button className="btn" onClick={save} disabled={!selection.length || !!busy}>Save selection</button>{selection.length > 0 && <button className="btn ghost" onClick={() => setPicks({})}>Clear</button>}</div>
      </aside>
    </div>
  );
}

function SavedReports({ conn, onOpen, onReport }: { conn: Conn; onOpen: (s: Saved) => void; onReport: (r: Report) => void }) {
  const { toast, confirm } = useApp();
  const list = usePoll(() => api<Saved[]>(`/databases/${conn.id}/reports`), [conn.id], 0);
  const [busy, setBusy] = useState<number | null>(null);
  async function run(s: Saved) { setBusy(s.id); try { onReport(await post<Report>(`/databases/${conn.id}/report`, { selection: s.selection, sample_rows: s.sample_rows, title: s.name })); } catch (e) { toast((e as Error).message, true); } finally { setBusy(null); } }
  async function remove(s: Saved) { if (!(await confirm(`Delete the saved report "${s.name}"?`))) return; await del(`/db-reports/${s.id}`); void list.reload(); }
  if (!list.value) return <div className="card"><p className="muted">Loading…</p></div>;
  if (!list.value.length) return <div className="card"><Empty title="No saved reports">Choose tables in the Report builder and press Save selection. Saved reports read fresh data every time.</Empty></div>;
  return (
    <section className="card"><table className="tbl"><thead><tr><th>Report</th><th className="hide-sm">Tables</th><th className="hide-sm">Saved</th><th /></tr></thead><tbody>
      {list.value.map(s => <tr key={s.id}><td><b>{s.name}</b><div className="muted sm">{s.sample_rows ? `${s.sample_rows} sample rows` : 'statistics only'}{s.created_by ? ` · ${s.created_by}` : ''}</div></td>
        <td className="hide-sm sm">{s.selection.map(p => p.table.split('.').pop()).join(', ')}</td><td className="hide-sm sm muted">{timeAgo(s.updated_at)}</td>
        <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}><button className="btn sm primary" onClick={() => run(s)} disabled={busy === s.id}>{busy === s.id ? 'Running…' : 'Run'}</button> <button className="btn sm" onClick={() => onOpen(s)}>Edit</button> <button className="btn sm danger" onClick={() => remove(s)}>Delete</button></td></tr>)}
    </tbody></table></section>
  );
}

/* ---------------------------------------------------------------- the report document */
function toMarkdown(r: Report): string {
  const out = [`# ${r.title}`, '', `${r.database.name} (${r.database.engine} ${r.database.server_version ?? ''}) · generated ${new Date(r.generated_at).toLocaleString()}`, '', r.overview, ''];
  if (r.relations.length) out.push('## Relationships', '', ...r.relations.map(x => `- ${x.text}`), '');
  for (const s of r.tables) {
    out.push(`## ${s.schema}.${s.name}`, '', s.summary, '');
    if (s.quality.length) out.push('**Data quality**', '', ...s.quality.map(q => `- ${q}`), '');
    out.push('| Column | Type | Filled | Distinct | Range / common values |', '|---|---|---|---|---|');
    s.profile.columns.forEach(c => out.push(`| ${c.name}${c.pk ? ' (key)' : ''} | ${c.type} | ${c.null_pct != null ? `${(100 - c.null_pct).toFixed(1)}%` : '–'} | ${c.distinct ?? '–'} | ${c.sensitive ? 'masked' : c.min != null ? `${shown(c.min)} … ${shown(c.max)}` : (c.top ?? []).map(t => `${shown(t.value)} (${t.pct}%)`).join(', ')} |`));
    out.push('');
  }
  return out.join('\n');
}

function ReportView({ report, onClose }: { report: Report; onClose: () => void }) {
  const download = () => { const url = URL.createObjectURL(new Blob([toMarkdown(report)], { type: 'text/markdown' })); const a = document.createElement('a'); a.href = url; a.download = `${report.title.replace(/[^A-Za-z0-9_-]+/g, '_').slice(0, 60) || 'report'}.md`; a.click(); URL.revokeObjectURL(url); };
  useEffect(() => { const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); }; window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k); }, [onClose]);
  return (
    <div className="db-report-overlay">
      <div className="db-report-bar no-print"><b>{report.title}</b><span className="grow" /><button className="btn sm" onClick={() => window.print()}>Print / save as PDF</button><button className="btn sm" onClick={download}>Download Markdown</button><button className="btn sm ghost" onClick={onClose} aria-label="Close"><Icon name="x" /></button></div>
      <article className="db-report">
        <header><div className="muted sm">{report.database.name} · {ENGINE_LABEL[report.database.engine as Conn['engine']] ?? report.database.engine} {report.database.server_version ?? ''} · {report.database.database}</div>
          <h1>{report.title}</h1><div className="muted sm">Generated {new Date(report.generated_at).toLocaleString()} · read-only snapshot</div></header>
        <section className="db-r-summary"><p>{report.overview}</p>
          <div className="db-r-kpis"><div><b>{report.tables.length}</b><small>{words(report.engine).table}s</small></div><div><b>{num(report.tables.reduce((a, s) => a + s.profile.rows, 0))}</b><small>{words(report.engine).rows}</small></div><div><b>{report.relations.length}</b><small>relationships</small></div><div><b className={report.issues ? 'warn' : 'good'}>{report.issues}</b><small>quality notes</small></div></div>
          {report.relations.length > 0 && <><h2>How the {words(report.engine).table}s relate</h2><ul>{report.relations.map((x, i) => <li key={i}>{x.text}</li>)}</ul></>}
          <h2>Contents</h2><ol className="db-r-toc">{report.tables.map(s => <li key={s.table}><a href={`#t-${s.table}`}>{s.name}</a> <span className="muted">· {num(s.profile.rows)} {words(report.engine).rows}{s.quality.length ? ` · ${s.quality.length} note${s.quality.length > 1 ? 's' : ''}` : ''}</span></li>)}</ol>
        </section>
        {report.tables.map(s => (
          <section key={s.table} id={`t-${s.table}`} className="db-r-table">
            <h2>{s.name} <span className="muted">{s.schema}{s.kind === 'view' ? ' · view' : ''}</span></h2>
            {s.comment && <p className="db-r-comment">{s.comment}</p>}
            <p>{s.summary}</p>
            <div className="db-r-facts"><span>{words(report.engine).rows[0].toUpperCase() + words(report.engine).rows.slice(1)} <b>{num(s.profile.rows)}{s.profile.rows_exact ? '' : ' (estimate)'}</b></span><span>Size <b>{bytes(s.size_bytes)}</b></span><span>Key <b>{s.primary_key.join(' + ') || 'none'}</b></span><span>Read in <b>{s.profile.seconds}s</b></span></div>
            {(s.references.length > 0 || s.referenced_by.length > 0) && <ul className="db-r-rels">{[...s.references, ...s.referenced_by].map((x, i) => <li key={i}>{x.text}</li>)}</ul>}
            {s.quality.length > 0 && <div className="db-r-quality"><b>Data quality</b><ul>{s.quality.map((q, i) => <li key={i}>{q}</li>)}</ul></div>}
            <table className="db-r-cols"><thead><tr><th>{words(report.engine).col[0].toUpperCase() + words(report.engine).col.slice(1)}</th><th>Type</th><th>Filled</th><th className="num">Distinct</th><th>Values</th></tr></thead><tbody>
              {s.profile.columns.map(c => <tr key={c.name}>
                <td><b>{c.name}</b>{c.pk && <span className="tag">key</span>}{c.unique && !c.pk && <span className="tag">unique</span>}{c.comment && <div className="muted sm">{c.comment}</div>}</td>
                <td className="mono sm">{c.type}{!c.nullable && <div className="muted sm">required</div>}</td>
                <td>{c.error ? '–' : <><div className="db-fill"><i style={{ width: `${100 - (c.null_pct ?? 0)}%` }} className={(c.null_pct ?? 0) >= 50 ? 'warn' : ''} /></div><span className="sm">{(100 - (c.null_pct ?? 0)).toFixed(1)}%{c.nulls ? <span className="muted"> · {num(c.nulls)} empty</span> : null}</span></>}</td>
                <td className="num">{num(c.distinct)}</td>
                <td className="sm">{c.error ? <span className="warn">{c.error}</span> : c.sensitive ? <span className="muted">values hidden (sensitive)</span> : <>
                  {c.min != null && <div>{shown(c.min)} → {shown(c.max)}{c.avg != null && <span className="muted"> · avg {shown(c.avg)}</span>}</div>}
                  {c.avg_length != null && c.min == null && !c.top && <div className="muted">avg length {c.avg_length}</div>}
                  {c.top && <div className="db-top">{c.top.map((t, i) => <span key={i}><b>{shown(t.value)}</b> {t.pct}%</span>)}</div>}</>}</td></tr>)}
            </tbody></table>
            {s.profile.sample.length > 0 && <><h3>Sample {words(report.engine).rows}</h3><div className="tbl-wrap"><table className="db-r-sample"><thead><tr>{s.profile.columns.map(c => <th key={c.name}>{c.name}</th>)}</tr></thead><tbody>
              {s.profile.sample.map((row, i) => <tr key={i}>{row.map((v, j) => <td key={j}>{v == null ? <span className="muted">null</span> : String(v)}</td>)}</tr>)}</tbody></table></div></>}
            {s.profile.notes.map((n, i) => <p key={i} className="muted sm">{n}</p>)}
          </section>))}
      </article>
    </div>
  );
}
