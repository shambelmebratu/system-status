import './globals.css';
import type { Metadata, Viewport } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';

// Self-hosted at build time: the browser never contacts Google, and the strict CSP (font-src 'self') stays as it is.
const inter = Inter({ subsets: ['latin'], variable: '--font-inter', display: 'swap' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jb', display: 'swap', weight: ['400', '500', '600'] });

export const metadata: Metadata = { title: 'SM-Watch', description: 'Infrastructure and uptime monitoring', icons: { icon: [{ url: '/icon.svg', type: 'image/svg+xml' }, { url: '/favicon.ico', sizes: 'any' }], apple: '/apple-icon.png' } };
export const viewport: Viewport = { themeColor: '#0b1220', width: 'device-width', initialScale: 1 };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning className={`${inter.variable} ${mono.variable}`}>
      <head>
        {/* Apply the saved theme before first paint to avoid a flash. */}
        <script dangerouslySetInnerHTML={{ __html: "try{var t=localStorage.getItem('smw_theme');if(t)document.documentElement.dataset.theme=t}catch(e){}" }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
