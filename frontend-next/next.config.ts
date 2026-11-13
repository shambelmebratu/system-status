import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  output: 'standalone',
  // Log requests are long-polled (held open up to ~20s); the default 30s proxy timeout is too close for comfort.
  experimental: { proxyTimeout: 60_000 },
  async rewrites() {
    return [{ source: '/api/:path*', destination: `${process.env.BACKEND_URL || 'http://api:8000'}/api/:path*` }];
  },
};

export default nextConfig;
