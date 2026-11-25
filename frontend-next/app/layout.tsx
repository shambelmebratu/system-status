// Fonts ship inside the app (npm packages): neither the build nor the browser contacts Google, so an offline or restricted build
// machine still builds, and the strict CSP (font-src 'self') stays as it is. Their variables are set in globals.css.
import '@fontsource-variable/inter/wght.css';
import '@fontsource-variable/jetbrains-mono/wght.css';
import './globals.css';
import type { Metadata, Viewport } from 'next';

export const metadata: Metadata = { title: 'SM-Watch', description: 'Infrastructure and uptime monitoring', icons: { icon: [{ url: '/icon.svg', type: 'image/svg+xml' }, { url: '/favicon.ico', sizes: 'any' }], apple: '/apple-icon.png' } };
export const viewport: Viewport = { themeColor: '#0b1220', width: 'device-width', initialScale: 1 };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Apply the saved theme before first paint to avoid a flash. */}
        <script dangerouslySetInnerHTML={{ __html: "try{var t=localStorage.getItem('smw_theme');if(t)document.documentElement.dataset.theme=t}catch(e){}" }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
