'use client';

/* "Jump anywhere" (⌘K / Ctrl+K): every page you can open, the Security sections, and each server and service by name. */
import { useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from './ui';
import { useApp } from '../lib/app';

export type PaletteItem = { id: string; label: string; hint?: string; icon: string; path: string; group: string };

export function CommandPalette({ pages, onClose }: { pages: PaletteItem[]; onClose: () => void }) {
  const { data, go } = useApp();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  useEffect(() => { input.current?.focus(); }, []);

  const items = useMemo<PaletteItem[]>(() => {
    const monitors: PaletteItem[] = [
      ...(data?.servers ?? []).map(s => ({ id: `s${s.id}`, label: s.name, hint: [s.last_metrics?.hostname || s.host, s.last_status].filter(Boolean).join(' · '), icon: 'server', path: `servers/${s.id}`, group: 'Servers' })),
      ...(data?.services ?? []).map(s => ({ id: `w${s.id}`, label: s.name, hint: [s.url, s.last_status].filter(Boolean).join(' · '), icon: 'globe', path: `services/${s.id}`, group: 'Services' })),
    ];
    const all = [...pages, ...monitors];
    const words = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!words.length) return all.slice(0, 60);
    return all.filter(i => { const hay = `${i.group} ${i.label} ${i.hint ?? ''}`.toLowerCase(); return words.every(w => hay.includes(w)); }).slice(0, 60);
  }, [data, pages, q]);

  useEffect(() => setSel(0), [q]);
  useEffect(() => { list.current?.querySelector('.on')?.scrollIntoView({ block: 'nearest' }); }, [sel]);

  const open = (i?: PaletteItem) => { if (!i) return; onClose(); go(i.path); };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(items.length - 1, s + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(0, s - 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); open(items[sel]); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };

  let lastGroup = '';
  return (
    <div className="overlay cmdk-overlay" onMouseDown={e => e.target === e.currentTarget && onClose()}>
      <div className="cmdk" role="dialog" aria-modal="true" aria-label="Jump anywhere" onKeyDown={onKey}>
        <div className="cmdk-input"><Icon name="search" size={16} />
          <input ref={input} value={q} onChange={e => setQ(e.target.value)} placeholder="Jump to a page, server or service…" aria-label="Search" />
          <kbd>Esc</kbd></div>
        <div className="cmdk-list" ref={list} role="listbox">
          {items.length === 0 ? <div className="cmdk-empty">Nothing matches “{q}”.</div> : items.map((i, n) => {
            const head = i.group !== lastGroup ? (lastGroup = i.group) : null;
            return <div key={i.id}>
              {head && <div className="cmdk-group">{head}</div>}
              <button type="button" role="option" aria-selected={n === sel} className={`cmdk-item ${n === sel ? 'on' : ''}`} onMouseMove={() => setSel(n)} onClick={() => open(i)}>
                <Icon name={i.icon} size={15} /><span className="cmdk-label">{i.label}</span>{i.hint && <span className="cmdk-hint">{i.hint}</span>}<Icon name="chevron-right" size={14} />
              </button></div>;
          })}
        </div>
        <div className="cmdk-foot"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>Esc</kbd> close</span></div>
      </div>
    </div>
  );
}
