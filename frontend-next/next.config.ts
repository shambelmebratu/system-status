import type { NextConfig } from 'next';

const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },                 // the dashboard must never be framed by another site (clickjacking)
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
];

// Everything the dashboard loads comes from its own origin, so the browser is told to refuse anything else. Next.js needs inline
// scripts/styles; development additionally needs eval for hot reloading.
const dev = process.env.NODE_ENV !== 'production';
securityHeaders.push({
  key: 'Content-Security-Policy',
  value: [
    "default-src 'self'", `script-src 'self' 'unsafe-inline'${dev ? " 'unsafe-eval'" : ''}`, "style-src 'self' 'unsafe-inline'", "img-src 'self' data: blob:",
    "font-src 'self' data:", `connect-src 'self'${dev ? ' ws: wss:' : ''}`, "object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'self'",
  ].join('; '),
});

const nextConfig: NextConfig = {
  output: 'standalone',
  poweredByHeader: false,                                           // do not advertise the framework
  // The image optimizer (and its native "sharp" library) is not used by this app: switch it off (the Dockerfile also
  // removes sharp from the container).
  images: { unoptimized: true },
  // Log requests are long-polled (held open up to ~20s); the default 30s proxy timeout is too close for comfort.
  experimental: { proxyTimeout: 60_000 },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
  async rewrites() {
    return [{ source: '/api/:path*', destination: `${process.env.BACKEND_URL || 'http://api:8000'}/api/:path*` }];
  },
};

export default nextConfig;
