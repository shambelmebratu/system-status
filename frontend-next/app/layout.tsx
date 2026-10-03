import './globals.css';

export const metadata = { title: 'Northstar Operations', description: 'Infrastructure monitoring control plane' };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
