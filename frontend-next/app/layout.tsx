import './globals.css';
import type { Metadata, Viewport } from 'next';

export const metadata: Metadata = { title: 'Northstar Operations', description: 'Infrastructure and uptime monitoring' };
export const viewport: Viewport = { themeColor: '#0b1220', width: 'device-width', initialScale: 1 };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Apply the saved theme before first paint to avoid a flash. */}
        <script dangerouslySetInnerHTML={{ __html: "try{var t=localStorage.getItem('ns_theme');if(t)document.documentElement.dataset.theme=t}catch(e){}" }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
