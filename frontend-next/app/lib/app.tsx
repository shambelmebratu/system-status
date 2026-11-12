'use client';

import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { api } from './api';
import type { Channel, Dashboard } from './types';

type Toast = { id: number; text: string; error: boolean };
type Ctx = {
  data: Dashboard | null; channels: Channel[]; refresh: () => Promise<void>; toast: (text: string, error?: boolean) => void;
  go: (path: string) => void; route: string[];
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

export function AppProvider({ children, onUnauthorized }: { children: ReactNode; onUnauthorized: () => void }) {
  const [data, setData] = useState<Dashboard | null>(null);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [route, go] = useRoute();
  const seq = useRef(0);

  const refresh = useCallback(async () => {
    try {
      const [dashboard, channelList] = await Promise.all([api<Dashboard>('/dashboard'), api<Channel[]>('/channels')]);
      setData(dashboard); setChannels(channelList);
    } catch (error) {
      if ((error as { status?: number }).status === 401) onUnauthorized();
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
    <AppContext.Provider value={{ data, channels, refresh, toast, go, route }}>
      {children}
      <div className="toasts" aria-live="polite">{toasts.map(t => <div key={t.id} className={`toast ${t.error ? 'error' : ''}`}>{t.text}</div>)}</div>
    </AppContext.Provider>
  );
}

/** Re-runs `load` on an interval (and when deps change); returns data, loading and a manual reload. */
export function usePoll<T>(load: () => Promise<T>, deps: unknown[], intervalMs = 15000) {
  const [value, setValue] = useState<T | null>(null);
  const [error, setError] = useState('');
  const fn = useRef(load);
  fn.current = load;
  const reload = useCallback(async () => {
    try { setValue(await fn.current()); setError(''); } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => {
    setValue(null);
    void reload();
    const timer = window.setInterval(() => { if (!document.hidden) void reload(); }, intervalMs);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { value, error, reload };
}
