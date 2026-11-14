'use client';

import { useId } from 'react';

/** The SM-Watch mark: an eye (watching) with a heartbeat (monitoring). Its colours follow the configured brand colours
 *  (BRAND_PRIMARY_COLOR / BRAND_ACCENT_COLOR), so a re-branded install gets a matching logo. */
export function Logo({ size = 30 }: { size?: number }) {
  const id = useId().replace(/:/g, '');
  return (
    <svg className="logo" width={size} height={size} viewBox="0 0 64 64" role="img" aria-label="Logo">
      <defs>
        <linearGradient id={id} x1="6" y1="4" x2="58" y2="60" gradientUnits="userSpaceOnUse">
          <stop offset="0" style={{ stopColor: 'var(--brand-primary, #c9f36b)' }} />
          <stop offset="1" style={{ stopColor: 'var(--brand-accent, #68d5e8)' }} />
        </linearGradient>
      </defs>
      <rect width="64" height="64" rx="15" fill={`url(#${id})`} />
      <path d="M32 11.5C18.5 11.5 8.8 22 5.5 32c3.3 10 13 20.5 26.5 20.5S55.2 42 58.5 32C55.2 22 45.5 11.5 32 11.5z" fill="#08111f" />
      <path d="M13.5 33.5h9.5l4.5-11 6.5 20 4.5-9h11" fill="none" stroke={`url(#${id})`} strokeWidth="4.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
