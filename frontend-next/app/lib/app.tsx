'use client';

import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { api } from './api';
import type { Channel, Dashboard, Me } from './types';
import { ConfirmModal } from '../components/confirm';

type Toast = { id: number; text: string; error: boolean };
type Ctx = {
  data: Dashboard | null; channels: Channel[]; refresh: () => Promise<void>; toast: (text: string, error?: boolean) => void;
  go: (path: string) => void; route: string[];
  confirm: (message: string, opts?: { confirmLabel?: string; danger?: boolean }) => Promise<boolean>;
  me: Me; canOperate: boolean; canManage: boolean; isAdmin: boolean; reloadMe: () => Promise<void>;
};
const AppContext = createContext<Ctx>(null as never);
export const useApp = () => useContext(AppContext);

/** Hash-based routing keeps the app a single static page behind the API proxy. */
function useRoute(): [string[], (path: string) => void] {
  const read = () => (typeof window === 'undefined' ? [] : window.location.hash.replace(/^#\/?/, '').split('/').filter(Boolean));
  const [route, setRoute] = useState<string[]>([]);
  useEffect(() => {
    setRoute(read());
    const onChange = () => { setRoute(read()); window.scrollTo(0, 0); };
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return [route, (path: string) => { window.location.hash = path; }];
}

export function AppProvider({ children, me, reloadMe, onUnauthorized }: { children: ReactNode; me: Me; reloadMe: () => Promise<void>; onUnauthorized: () => void }) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [route, go] = useRoute();
  const seq = useRef(0);
  const [dialog, setDialog] = useState<{ message: string; confirmLabel?: string; danger?: boolean; resolve: (ok: boolean) => void } | null>(null);
  const confirm = useCallback((message: string, opts?: { confirmLabel?: string; danger?: boolean }) => new Promise<boolean>(resolve => setDialog({ message, ...opts, resolve })), []);

  const busy = useRef(false);
  const refresh = useCallback(async () => {
    if (busy.current) return;   // the previous refresh is still on its way: never stack requests on a slow link
    busy.current = true;
    try {
      const [dashboard, channelList] = await Promise.all([api<Dashboard>('/dashboard'), api<Channel[]>('/channels')]);
      setData(dashboard); setChannels(channelList);
    } catch (error) {
      if ((error as { status?: number }).status === 401) onUnauthorized();
    } finally {
      busy.current = false;
    }
  }, [onUnauthorized]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => { if (!document.hidden) void refresh(); }, 10000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const toast = useCallback((text: string, error = false) => {
    const id = ++seq.current;
    setToasts(list => [...list, { id, text, error }]);
    window.setTimeout(() => setToasts(list => list.filter(item => item.id !== id)), error ? 7000 : 4000);
  }, []);

  return (
    <AppContext.Provider value={{ data, channels, refresh, toast, confirm, go, route, me, canOperate: me.role !== 'viewer', canManage: me.role !== 'viewer' && !me.access /* add/remove monitors, links, channels: not for people limited to selected monitors */, isAdmin: me.role === 'admin', reloadMe }}>
      {children}
      {dialog && <ConfirmModal {...dialog} onClose={ok => { dialog.resolve(ok); setDialog(null); }} />}
      <div className="toasts" aria-live="polite">{toasts.map(t => <div key={t.id} className={`toast ${t.error ? 'error' : ''}`}>{t.text}</div>)}</div>
    </AppContext.Provider>
  );
}

/** Operational limits configured in .env (served by the API, so nothing is hard-coded in the UI). */
export function useLimits() {
  const { data } = useApp();
  const l = data?.limits;
  return {
    warn: l?.usage_warn_percent ?? 70, bad: l?.usage_bad_percent ?? 90, offlineMs: (l?.k8s_offline_seconds ?? 120) * 1000,
    reminder: l?.reminder_minutes ?? 30, enrollDefault: l?.enrollment_default_minutes ?? 15, enrollMax: l?.enrollment_max_minutes ?? 1440, logTtl: l?.log_result_ttl_minutes ?? 15,
    serviceTimeout: l?.service_timeout_seconds ?? 10, certDays: (l?.cert_alert_days ?? '30,14,7').split(',').map(Number).filter(Boolean), certHours: l?.cert_check_hours ?? 6,
  };
}

/** The current time, re-read every second: keeps "12s ago" labels counting instead of freezing until the next data refresh. */
export function useNow(ms = 1000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), ms); return () => clearInterval(t); }, [ms]);
  return now;
}

/** Re-runs `load` on an interval (and when deps change); returns data, loading and a manual reload.
 *  - A tick is skipped while the previous request is still running, so a slow connection never piles requests up.
 *  - An answer that arrives after the deps changed is ignored (it belongs to the previous page or range).
 *  - keepWhileLoading: show the previous data until the new answer arrives (e.g. switching a graph's range) instead of a blank. */
export function usePoll<T>(load: () => Promise<T>, deps: unknown[], intervalMs = 15000, keepWhileLoading = false) {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const fn = useRef(load);
  fn.current = load;
  const generation = useRef(0);
  const inFlight = useRef(false);
  const run = useCallback(async (mine: number) => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      const result = await fn.current();
      if (mine === generation.current) { setValue(result); setError(''); }
    } catch (e) {
      if (mine === generation.current) setError((e as Error).message);
    } finally {
      if (mine === generation.current) { inFlight.current = false; setLoading(false); }
    }
  }, []);
  const reload = useCallback(() => { generation.current++; inFlight.current = false; return run(generation.current); }, [run]);
  useEffect(() => {
    generation.current++;
    inFlight.current = false;
    const mine = generation.current;
    if (!keepWhileLoading) setValue(null);
    setLoading(true);
    void run(mine);
    if (intervalMs <= 0) return;   // 0 = load once (reload() refreshes on demand)
    const timer = window.setInterval(() => { if (!document.hidden && mine === generation.current) void run(mine); }, intervalMs);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { value, error, reload, loading };
}


/** How often a graph over `range` needs fresh data: a 30-day chart does not change every 10 seconds. */
export const pollFor = (range: string) => ({ '1m': 5000, '5m': 5000, '15m': 15000, '30m': 15000, '1h': 10000, '4h': 30000, '6h': 15000, '12h': 60000, '24h': 30000, '1d': 60000, '7d': 120000, '30d': 300000, '1mo': 300000, '3mo': 600000, '1y': 900000 } as Record<string, number>)[range] ?? 30000;
