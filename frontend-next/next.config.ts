import type { NextConfig } from 'next';

const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },                 // the dashboard must never be framed by another site (clickjacking)
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=()' },
  { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
];

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
