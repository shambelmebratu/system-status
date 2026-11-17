'use client';

import { FormEvent, useState } from 'react';
import { MonitorAlertSettings, alertsOf, type MonitorAlerts } from '../components/alertpick';
import { Empty, Field, Icon, Modal, StatusPill } from '../components/ui';
import { api, del, post, put } from '../lib/api';
import { useApp, usePoll } from '../lib/app';
import { ms, timeAgo, uptimeClass } from '../lib/format';

/* ---------------------------------------------------------------- types */
type Assertion = { kind: 'status' | 'json' | 'header' | 'body' | 'time'; path: string; op: string; value: string };
type Extract = { var: string; source: 'json' | 'header' | 'status' | 'body'; path: string };
type Step = { name: string; method: string; url: string; headers: Record<string, string>; body: string; timeout_seconds: number; assertions: Assertion[]; extract: Extract[] };
type Definition = { steps: Step[]; variables: Record<string, string>; secret_variables: string[] };
type Test = MonitorAlerts & { id: number; name: string; description: string; enabled: boolean; interval_seconds: number; last_status: string; last_run_at: string | null; last_duration_ms: number | null;
  last_error: string | null; step_count: number; pass_rate_7d?: number | null; definition?: Definition; created_by: string | null };
type Check = { text: string; ok: boolean; actual: string };
type StepResult = { name: string; method: string; url: string; status: 'passed' | 'failed' | 'error' | 'skipped'; status_code?: number; ms?: number; error?: string; checks?: Check[];
  request_headers?: Record<string, string>; request_body?: string; response_headers?: Record<string, string>; response_body?: string; truncated?: boolean; size?: number; extracted?: string[] };
type RunResult = { status: 'passed' | 'failed'; duration_ms: number; steps: StepResult[]; error: string | null; run_id?: number };
type Run = { id: number; test_id: number; started_at: string; duration_ms: number; status: 'passed' | 'failed'; trigger: string; error: string | null; steps?: StepResult[]; test_name?: string };

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const OPS: Record<Assertion['kind'], [string, string][]> = {
  status: [['eq', 'equals'], ['ne', 'is not'], ['in', 'is one of'], ['lt', 'is below'], ['gte', 'is at least']],
  json: [['eq', 'equals'], ['ne', 'is not'], ['contains', 'contains'], ['not_contains', 'does not contain'], ['exists', 'exists'], ['not_exists', 'does not exist'], ['gt', 'is greater than'], ['lt', 'is less than'], ['gte', 'is at least'], ['lte', 'is at most'], ['matches', 'matches regex'], ['type', 'is of type']],
  header: [['exists', 'exists'], ['eq', 'equals'], ['contains', 'contains'], ['matches', 'matches regex'], ['not_exists', 'does not exist']],
  body: [['contains', 'contains'], ['not_contains', 'does not contain'], ['matches', 'matches regex']],
  time: [['lt', 'is below (ms)'], ['lte', 'is at most (ms)']],
};
const KIND_LABEL: Record<Assertion['kind'], string> = { status: 'Status code', json: 'JSON value', header: 'Header', body: 'Body text', time: 'Response time' };
const newStep = (n: number): Step => ({ name: `Step ${n}`, method: 'GET', url: 'https://', headers: {}, body: '', timeout_seconds: 10, assertions: [{ kind: 'status', path: '', op: 'eq', value: '200' }], extract: [] });
const every = (s: number) => (s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`);
const stepTone = (s: string) => (s === 'passed' ? 'good' : s === 'skipped' ? 'muted' : 'bad');

/* ---------------------------------------------------------------- page */
export function Tests() {
  const { route, go, canManage } = useApp();
  const list = usePoll(() => api<Test[]>('/tests'), [], 20000);
  const [editing, setEditing] = useState<Test | 'new' | null>(null);
  const id = Number(route[1]);
  if (route[1] === 'run' && route[2]) return <RunReport runId={Number(route[2])} />;
  if (id) return <TestDetail id={id} onEdit={t => setEditing(t)} editing={editing} closeEdit={() => { setEditing(null); void list.reload(); }} />;
  const tests = list.value ?? [];
  return (
    <>
      <div className="topbar"><div><h1>API tests</h1><p className="muted sm">Multi-step checks of your APIs: log in, carry the token, call endpoints, check status codes, JSON values, headers and timings.</p></div>
        <span className="grow" />{canManage && <button className="btn primary" onClick={() => setEditing('new')}><Icon name="plus" size={15} />New test</button>}</div>
      {list.error && <div className="err">{list.error}</div>}
      <div className="card">
        {list.value && tests.length === 0 ? <Empty title="No API tests yet" action={canManage ? <button className="btn primary" onClick={() => setEditing('new')}>Create your first test</button> : undefined}>
          A test is a sequence of requests with assertions, run on a schedule. A failing test raises an incident and alerts like any monitor.</Empty> : (
          <table className="tbl"><thead><tr><th>Test</th><th>Status</th><th className="num hide-sm">Steps</th><th className="num">Passed (7d)</th><th className="num hide-sm">Last run</th><th className="hide-sm">Every</th></tr></thead><tbody>
            {tests.map(t => <tr key={t.id} className="link" onClick={() => go(`tests/${t.id}`)}>
              <td><div className="name">{t.name}{!t.enabled && <> <span className="tag">paused</span></>}<small>{t.last_error && t.last_status !== 'up' ? <span className="bad">{t.last_error}</span> : t.description}</small></div></td>
              <td><StatusPill status={t.last_status === 'up' ? 'up' : t.last_status} label={t.last_status === 'up' ? 'Passing' : t.last_status === 'down' ? 'Failing' : 'Not run yet'} /></td>
              <td className="num hide-sm">{t.step_count}</td><td className={`num ${uptimeClass(t.pass_rate_7d)}`}>{t.pass_rate_7d == null ? '–' : `${t.pass_rate_7d.toFixed(1)}%`}</td>
              <td className="num hide-sm sm">{t.last_run_at ? <>{ms(t.last_duration_ms)} <span className="muted">· {timeAgo(t.last_run_at)}</span></> : '–'}</td><td className="hide-sm sm muted">{every(t.interval_seconds)}</td></tr>)}
          </tbody></table>)}
      </div>
      {editing && <TestEditor existing={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={t => { setEditing(null); void list.reload(); go(`tests/${t.id}`); }} />}
    </>
  );
}

/* ---------------------------------------------------------------- one test */
function TestDetail({ id, onEdit, editing, closeEdit }: { id: number; onEdit: (t: Test) => void; editing: Test | 'new' | null; closeEdit: () => void }) {
  const { go, toast, confirm, canManage, refresh } = useApp();
  const test = usePoll(() => api<Test>(`/tests/${id}`), [id], 20000);
  const runs = usePoll(() => api<{ runs: Run[]; summary_7d: { runs: number; passed: number; avg_ms: number | null } }>(`/tests/${id}/runs?limit=100`), [id], 20000);
  const [busy, setBusy] = useState(false);
  const [last, setLast] = useState<RunResult | null>(null);
  const t = test.value;
  async function runNow() {
    setBusy(true);
    try { const r = await post<RunResult>(`/tests/${id}/run`); setLast(r); toast(r.status === 'passed' ? `Passed in ${Math.round(r.duration_ms)} ms` : `Failed: ${r.error}`, r.status !== 'passed'); await Promise.all([test.reload(), runs.reload()]); void refresh(); }
    catch (e) { toast((e as Error).message, true); } finally { setBusy(false); }
  }
  async function remove() {
    if (!t || !(await confirm(`Delete the test "${t.name}"?\n\nIts run history is deleted too.`))) return;
    await del(`/tests/${id}`); toast('Test deleted'); go('tests');
  }
  if (test.error) return <div className="err">{test.error}</div>;
  if (!t) return <div className="card"><p className="muted">Loading…</p></div>;
  const s = runs.value?.summary_7d;
  const history = [...(runs.value?.runs ?? [])].reverse();
  return (
    <>
      <div className="topbar">
        <button className="btn ghost sm" onClick={() => go('tests')}><Icon name="back" size={15} />API tests</button>
        <h1>{t.name}</h1><StatusPill status={t.last_status} label={t.last_status === 'up' ? 'Passing' : t.last_status === 'down' ? 'Failing' : 'Not run yet'} /><span className="grow" />
        {canManage && <button className="btn sm primary" onClick={runNow} disabled={busy}><Icon name="refresh" size={14} />{busy ? 'Running…' : 'Run now'}</button>}
        {canManage && <button className="btn sm" onClick={() => onEdit(t)}>Edit</button>}
        {canManage && <button className="btn sm danger" onClick={remove}>Delete</button>}
      </div>
      {t.description && <p className="muted" style={{ marginTop: -12 }}>{t.description}</p>}
      {t.last_status === 'down' && t.last_error && <div className="err" style={{ marginBottom: 14 }}>{t.last_error}</div>}
      <div className="ssh-stats" style={{ marginBottom: 14 }}>
        <div className="card ssh-stat"><small>Passed (7 days)</small><b className={uptimeClass(t.pass_rate_7d)}>{t.pass_rate_7d == null ? '–' : `${t.pass_rate_7d.toFixed(1)}%`}</b><span className="muted sm">{s ? `${s.passed} of ${s.runs} runs` : ''}</span></div>
        <div className="card ssh-stat"><small>Average duration</small><b>{ms(s?.avg_ms)}</b><span className="muted sm">all steps, last 7 days</span></div>
        <div className="card ssh-stat"><small>Steps</small><b>{t.step_count}</b><span className="muted sm">runs every {every(t.interval_seconds)}{t.enabled ? '' : ' (paused)'}</span></div>
        <div className="card ssh-stat"><small>Last run</small><b className="sm-b">{t.last_run_at ? timeAgo(t.last_run_at) : 'never'}</b><span className="muted sm">{ms(t.last_duration_ms)}</span></div>
      </div>
      <section className="card"><div className="card-head"><h2>Run history</h2><span className="grow" /><span className="muted sm">newest on the right · click a bar for its report</span></div>
        {history.length === 0 ? <p className="muted">No runs yet. Press Run now.</p> : <div className="qa-bars">{history.map(r => <button key={r.id} className={`qa-bar ${r.status}`} title={`${new Date(r.started_at).toLocaleString()} · ${r.status} · ${Math.round(r.duration_ms)} ms`} onClick={() => go(`tests/run/${r.id}`)} style={{ height: `${Math.max(18, Math.min(100, (r.duration_ms / Math.max(...history.map(x => x.duration_ms), 1)) * 100))}%` }} />)}</div>}
        <table className="tbl" style={{ marginTop: 12 }}><thead><tr><th>When</th><th>Result</th><th className="num">Duration</th><th className="hide-sm">Trigger</th><th>Problem</th></tr></thead><tbody>
          {(runs.value?.runs ?? []).slice(0, 15).map(r => <tr key={r.id} className="link" onClick={() => go(`tests/run/${r.id}`)}><td className="sm">{new Date(r.started_at).toLocaleString()}</td>
            <td><span className={`qa-result ${r.status}`}>{r.status === 'passed' ? '✓ Passed' : '✗ Failed'}</span></td><td className="num">{ms(r.duration_ms)}</td><td className="hide-sm sm muted">{r.trigger}</td><td className="sm bad trunc" style={{ maxWidth: 380 }} title={r.error ?? ''}>{r.error}</td></tr>)}
        </tbody></table>
      </section>
      {last && <section className="card" style={{ marginTop: 14 }}><div className="card-head"><h2>Latest run</h2><span className="grow" />{last.run_id && <button className="btn sm" onClick={() => go(`tests/run/${last.run_id}`)}>Open report</button>}</div><StepResults steps={last.steps} /></section>}
      {editing && editing !== 'new' && <TestEditor existing={editing} onClose={closeEdit} onSaved={() => { closeEdit(); void test.reload(); }} />}
    </>
  );
}

/* ---------------------------------------------------------------- results */
function StepResults({ steps }: { steps: StepResult[] }) {
  const [open, setOpen] = useState<number | null>(() => { const i = steps.findIndex(s => s.status === 'failed' || s.status === 'error'); return i >= 0 ? i : null; });
  return (
    <div className="qa-steps">
      {steps.map((s, i) => (
        <div key={i} className={`qa-step ${s.status}`}>
          <button type="button" className="qa-step-head" onClick={() => setOpen(open === i ? null : i)} aria-expanded={open === i}>
            <span className={`qa-dot ${stepTone(s.status)}`}>{s.status === 'passed' ? '✓' : s.status === 'skipped' ? '–' : '✗'}</span>
            <b>{s.name}</b><span className="mono sm muted trunc">{s.method} {s.url}</span><span className="grow" />
            {s.status_code != null && <span className={`tag ${s.status_code >= 400 ? 'bad' : ''}`}>{s.status_code}</span>}{s.ms != null && <span className="sm muted">{Math.round(s.ms)} ms</span>}
          </button>
          {open === i && s.status !== 'skipped' && (
            <div className="qa-step-body">
              {s.error && <div className="err">{s.error}</div>}
              {s.checks && <ul className="qa-checks">{s.checks.map((c, j) => <li key={j} className={c.ok ? 'ok' : 'bad'}><span>{c.ok ? '✓' : '✗'}</span><div>{c.text}{!c.ok && <div className="sm muted">got <code>{c.actual}</code></div>}</div></li>)}</ul>}
              {!!s.extracted?.length && <p className="sm muted">Saved for later steps: {s.extracted.map(v => <code key={v}>{`{{${v}}}`}</code>)}</p>}
              <div className="qa-io">
                <div><h4>Request</h4><pre>{`${s.method} ${s.url}\n${Object.entries(s.request_headers ?? {}).map(([k, v]) => `${k}: ${v}`).join('\n')}${s.request_body ? `\n\n${s.request_body}` : ''}`}</pre></div>
                <div><h4>Response {s.size != null && <span className="muted sm">· {s.size.toLocaleString()} bytes</span>}</h4><pre>{`${s.status_code ?? ''}\n${Object.entries(s.response_headers ?? {}).slice(0, 12).map(([k, v]) => `${k}: ${v}`).join('\n')}\n\n${s.response_body ?? ''}${s.truncated ? '\n…' : ''}`}</pre></div>
              </div>
            </div>)}
        </div>))}
    </div>
  );
}

function RunReport({ runId }: { runId: number }) {
  const { go } = useApp();
  const run = usePoll(() => api<Run>(`/test-runs/${runId}`), [runId], 0);
  const r = run.value;
  if (run.error) return <div className="err">{run.error}</div>;
  if (!r) return <div className="card"><p className="muted">Loading…</p></div>;
  const steps = r.steps ?? [];
  const checks = steps.flatMap(s => s.checks ?? []);
  return (
    <>
      <div className="topbar no-print"><button className="btn ghost sm" onClick={() => go(`tests/${r.test_id ?? ''}`)}><Icon name="back" size={15} />Test</button><span className="grow" /><button className="btn sm" onClick={() => window.print()}>Print / save as PDF</button></div>
      <article className="card qa-report">
        <div className="muted sm">API test report</div>
        <h1>{r.test_name}</h1>
        <p className={`qa-verdict ${r.status}`}>{r.status === 'passed' ? '✓ All steps passed' : `✗ Failed: ${r.error}`}</p>
        <div className="ssh-stats">
          <div className="ssh-stat"><small>Run</small><b className="sm-b">{new Date(r.started_at).toLocaleString()}</b><span className="muted sm">{r.trigger}</span></div>
          <div className="ssh-stat"><small>Duration</small><b>{ms(r.duration_ms)}</b></div>
          <div className="ssh-stat"><small>Steps</small><b>{steps.filter(s => s.status === 'passed').length} / {steps.length}</b><span className="muted sm">passed</span></div>
          <div className="ssh-stat"><small>Assertions</small><b>{checks.filter(c => c.ok).length} / {checks.length}</b><span className="muted sm">passed</span></div>
        </div>
        <StepResults steps={steps} />
      </article>
    </>
  );
}

/* ---------------------------------------------------------------- editor */
function KeyValues({ value, onChange, keyLabel, valueLabel }: { value: [string, string][]; onChange: (v: [string, string][]) => void; keyLabel: string; valueLabel: string }) {
  return <div className="qa-kv">{value.map(([k, v], i) => (
    <div key={i} className="qa-kv-row"><input value={k} onChange={e => onChange(value.map((x, j) => (j === i ? [e.target.value, x[1]] : x)))} placeholder={keyLabel} />
      <input value={v} onChange={e => onChange(value.map((x, j) => (j === i ? [x[0], e.target.value] : x)))} placeholder={valueLabel} />
      <button type="button" className="btn ghost sm" onClick={() => onChange(value.filter((_, j) => j !== i))} aria-label="Remove"><Icon name="x" size={14} /></button></div>))}
    <button type="button" className="lg-link sm" onClick={() => onChange([...value, ['', '']])}>+ Add</button></div>;
}

function StepEditor({ step, index, count, onChange, onRemove, onMove, variables }: { step: Step; index: number; count: number; onChange: (s: Step) => void; onRemove: () => void; onMove: (d: number) => void; variables: string[] }) {
  const [open, setOpen] = useState(index === 0);
  const set = <K extends keyof Step>(k: K, v: Step[K]) => onChange({ ...step, [k]: v });
  const hasBody = !['GET', 'HEAD'].includes(step.method);
  return (
    <div className={`qa-edit-step ${open ? 'open' : ''}`}>
      <div className="qa-edit-head">
        <button type="button" className="qa-edit-toggle" onClick={() => setOpen(!open)}>{open ? '▾' : '▸'} <b>{index + 1}. {step.name || 'Untitled step'}</b> <span className="mono sm muted trunc">{step.method} {step.url}</span></button>
        <span className="grow" />
        <button type="button" className="btn ghost sm" onClick={() => onMove(-1)} disabled={index === 0} aria-label="Move up">↑</button>
        <button type="button" className="btn ghost sm" onClick={() => onMove(1)} disabled={index === count - 1} aria-label="Move down">↓</button>
        <button type="button" className="btn ghost sm" onClick={onRemove} disabled={count === 1} aria-label="Remove step"><Icon name="x" size={14} /></button>
      </div>
      {open && <div className="qa-edit-body">
        <div className="qa-req">
          <input value={step.name} onChange={e => set('name', e.target.value)} placeholder="Step name" maxLength={100} />
          <select value={step.method} onChange={e => set('method', e.target.value)}>{METHODS.map(m => <option key={m}>{m}</option>)}</select>
          <input className="mono" value={step.url} onChange={e => set('url', e.target.value)} placeholder="https://api.example.com/login" required />
          <select value={step.timeout_seconds} onChange={e => set('timeout_seconds', Number(e.target.value))} title="Timeout">{[5, 10, 20, 30, 60].map(n => <option key={n} value={n}>{n} s</option>)}</select>
        </div>
        <div className="qa-cols">
          <div><h4>Headers</h4><KeyValues value={Object.entries(step.headers)} onChange={v => set('headers', Object.fromEntries(v))} keyLabel="Authorization" valueLabel="Bearer {{token}}" /></div>
          {hasBody && <div><h4>Body</h4><textarea className="mono" rows={4} value={step.body} onChange={e => set('body', e.target.value)} placeholder={'{"user": "qa", "password": "{{password}}"}'} /></div>}
        </div>
        <h4>Assertions <span className="muted sm">(all must pass)</span></h4>
        {step.assertions.map((a, i) => { const ops = OPS[a.kind]; return (
          <div key={i} className="qa-assert">
            <select value={a.kind} onChange={e => { const kind = e.target.value as Assertion['kind']; set('assertions', step.assertions.map((x, j) => (j === i ? { ...x, kind, op: OPS[kind][0][0], path: kind === 'json' || kind === 'header' ? x.path : '' } : x))); }}>{(Object.keys(KIND_LABEL) as Assertion['kind'][]).map(k => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}</select>
            {(a.kind === 'json' || a.kind === 'header') && <input className="mono" value={a.path} onChange={e => set('assertions', step.assertions.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))} placeholder={a.kind === 'json' ? 'data.items[0].id' : 'content-type'} />}
            <select value={a.op} onChange={e => set('assertions', step.assertions.map((x, j) => (j === i ? { ...x, op: e.target.value } : x)))}>{ops.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
            {!['exists', 'not_exists'].includes(a.op) && <input value={a.value} onChange={e => set('assertions', step.assertions.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} placeholder={a.kind === 'status' ? '200' : a.op === 'type' ? 'string | number | array …' : 'value'} />}
            <button type="button" className="btn ghost sm" onClick={() => set('assertions', step.assertions.filter((_, j) => j !== i))} aria-label="Remove"><Icon name="x" size={14} /></button>
          </div>); })}
        <button type="button" className="lg-link sm" onClick={() => set('assertions', [...step.assertions, { kind: 'json', path: '', op: 'exists', value: '' }])}>+ Add assertion</button>
        <h4>Save values for later steps</h4>
        {step.extract.map((x, i) => (
          <div key={i} className="qa-assert">
            <input className="mono" value={x.var} onChange={e => set('extract', step.extract.map((y, j) => (j === i ? { ...y, var: e.target.value.replace(/[^A-Za-z0-9_]/g, '') } : y)))} placeholder="token" />
            <span className="muted sm">from</span>
            <select value={x.source} onChange={e => set('extract', step.extract.map((y, j) => (j === i ? { ...y, source: e.target.value as Extract['source'] } : y)))}><option value="json">JSON</option><option value="header">header</option><option value="status">status code</option><option value="body">whole body</option></select>
            {(x.source === 'json' || x.source === 'header') && <input className="mono" value={x.path} onChange={e => set('extract', step.extract.map((y, j) => (j === i ? { ...y, path: e.target.value } : y)))} placeholder={x.source === 'json' ? 'data.token' : 'x-request-id'} />}
            <button type="button" className="btn ghost sm" onClick={() => set('extract', step.extract.filter((_, j) => j !== i))} aria-label="Remove"><Icon name="x" size={14} /></button>
          </div>))}
        <button type="button" className="lg-link sm" onClick={() => set('extract', [...step.extract, { var: '', source: 'json', path: '' }])}>+ Save a value</button>
        {variables.length > 0 && <p className="muted sm" style={{ marginTop: 8 }}>Use variables anywhere as {variables.map(v => <code key={v}>{`{{${v}}}`}</code>)} and <code>{'{{$timestamp}}'}</code> <code>{'{{$uuid}}'}</code>.</p>}
      </div>}
    </div>
  );
}

function TestEditor({ existing, onClose, onSaved }: { existing?: Test; onClose: () => void; onSaved: (t: Test) => void }) {
  const def = existing?.definition;
  const [name, setName] = useState(existing?.name ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [interval, setIntervalValue] = useState(existing?.interval_seconds ?? 300);
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [steps, setSteps] = useState<Step[]>(def?.steps ?? [newStep(1)]);
  const [vars, setVars] = useState<[string, string][]>(Object.entries(def?.variables ?? {}));
  const [secret, setSecret] = useState<string[]>(def?.secret_variables ?? []);
  const [alerts, setAlerts] = useState<MonitorAlerts>(alertsOf(existing));
  const [trial, setTrial] = useState<RunResult | null>(null);
  const [busy, setBusy] = useState(''); const [error, setError] = useState('');
  const definition = (): Definition => ({ steps, variables: Object.fromEntries(vars.filter(([k]) => k)), secret_variables: secret.filter(s => vars.some(([k]) => k === s)) });
  const varNames = [...vars.map(([k]) => k).filter(Boolean), ...steps.flatMap(s => s.extract.map(x => x.var)).filter(Boolean)];
  async function tryIt() { setBusy('try'); setError(''); setTrial(null); try { setTrial(await post<RunResult>('/tests/try', definition())); } catch (e) { setError((e as Error).message); } finally { setBusy(''); } }
  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy('save'); setError('');
    const body = { name, description, interval_seconds: interval, enabled, definition: definition(), ...alerts };
    try { onSaved(existing ? await put<Test>(`/tests/${existing.id}`, body) : await post<Test>('/tests', body)); } catch (e2) { setError((e2 as Error).message); } finally { setBusy(''); }
  }
  return (
    <Modal title={existing ? `Edit ${existing.name}` : 'New API test'} onClose={onClose} wide>
      <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="form-grid">
          <Field label="Name"><input value={name} onChange={e => setName(e.target.value)} placeholder="Checkout API" required maxLength={100} autoFocus /></Field>
          <Field label="Run every"><select value={interval} onChange={e => setIntervalValue(Number(e.target.value))}>{[60, 300, 600, 900, 1800, 3600, 21600, 86400].map(s => <option key={s} value={s}>{every(s)}</option>)}</select></Field>
          <Field label="Description (optional)"><input value={description} onChange={e => setDescription(e.target.value)} maxLength={500} placeholder="Logs in and checks the order list" /></Field>
          <label className="check" style={{ alignSelf: 'end' }}><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />Run on schedule</label>
        </div>
        <fieldset className="cert-fs"><legend><b>Variables</b> <span className="muted sm">usable as {'{{name}}'}; tick secret ones so they never appear in results</span></legend>
          <div className="qa-kv">{vars.map(([k, v], i) => (
            <div key={i} className="qa-kv-row"><input className="mono" value={k} onChange={e => setVars(vars.map((x, j) => (j === i ? [e.target.value.replace(/[^A-Za-z0-9_]/g, ''), x[1]] : x)))} placeholder="password" />
              <input type={secret.includes(k) ? 'password' : 'text'} value={v} onChange={e => setVars(vars.map((x, j) => (j === i ? [x[0], e.target.value] : x)))} placeholder="value" autoComplete="off" />
              <label className="check sm"><input type="checkbox" checked={secret.includes(k)} onChange={e => setSecret(e.target.checked ? [...secret, k] : secret.filter(s => s !== k))} />secret</label>
              <button type="button" className="btn ghost sm" onClick={() => setVars(vars.filter((_, j) => j !== i))} aria-label="Remove"><Icon name="x" size={14} /></button></div>))}
            <button type="button" className="lg-link sm" onClick={() => setVars([...vars, ['', '']])}>+ Add variable</button></div>
        </fieldset>
        <div>
          {steps.map((s, i) => <StepEditor key={i} step={s} index={i} count={steps.length} variables={varNames} onChange={n => setSteps(steps.map((x, j) => (j === i ? n : x)))} onRemove={() => setSteps(steps.filter((_, j) => j !== i))}
            onMove={d => { const n = [...steps]; [n[i], n[i + d]] = [n[i + d], n[i]]; setSteps(n); }} />)}
          {steps.length < 20 && <button type="button" className="btn sm" onClick={() => setSteps([...steps, newStep(steps.length + 1)])}><Icon name="plus" size={13} />Add step</button>}
        </div>
        <MonitorAlertSettings kind="test" value={alerts} onChange={setAlerts} />
        {trial && <div className="card"><div className="card-head"><h2>Try-out result</h2><span className={`qa-result ${trial.status}`}>{trial.status === 'passed' ? '✓ Passed' : '✗ Failed'}</span><span className="muted sm">{Math.round(trial.duration_ms)} ms · not saved</span></div><StepResults steps={trial.steps} /></div>}
        {error && <div className="err" role="alert">{error}</div>}
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
          <button type="button" className="btn" onClick={tryIt} disabled={!!busy}>{busy === 'try' ? 'Running…' : 'Try it'}</button>
          <button type="button" className="btn ghost" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!!busy}>{busy === 'save' ? 'Saving…' : 'Save'}</button></div>
      </form>
    </Modal>
  );
}
