'use client';

import { useEffect, useRef } from 'react';
import { Icon } from './ui';

/** In-app replacement for window.confirm: styled, themed, keyboard friendly (Esc cancels, Enter confirms). */
export function ConfirmModal({ message, confirmLabel, danger, onClose }: { message: string; confirmLabel?: string; danger?: boolean; onClose: (ok: boolean) => void }) {
  const parts = message.split('\n\n');
  const title = parts.length > 1 ? parts[0] : 'Are you sure?';
  const body = parts.length > 1 ? parts.slice(1).join('\n\n') : parts[0];
  const isDanger = danger ?? /remove|delete|revoke|purge|permanently|cannot be undone/i.test(message);
  const okRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    okRef.current?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(false); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="overlay" style={{ placeItems: 'center' }} onMouseDown={e => e.target === e.currentTarget && onClose(false)}>
      <div className="modal confirm" role="alertdialog" aria-modal="true" aria-label={title} style={{ maxWidth: 440 }}>
        <div style={{ display: 'flex', gap: 14 }}>
          <span className={`confirm-icon ${isDanger ? 'danger' : ''}`}><Icon name={isDanger ? 'alert' : 'shield'} size={20} /></span>
          <div style={{ minWidth: 0 }}>
            <h2 style={{ fontSize: 17, margin: '2px 0 8px', textTransform: 'none', letterSpacing: 0, color: 'var(--ink)' }}>{title}</h2>
            <div className="sm muted" style={{ whiteSpace: 'pre-line', lineHeight: 1.55 }}>{body}</div>
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button className="btn" onClick={() => onClose(false)}>Cancel</button>
          <button ref={okRef} className={`btn ${isDanger ? 'danger solid' : 'primary'}`} onClick={() => onClose(true)}>{confirmLabel ?? (isDanger ? 'Yes, continue' : 'Confirm')}</button>
        </div>
      </div>
    </div>
  );
}
