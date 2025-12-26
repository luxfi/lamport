import type { ReactNode } from 'react'
import { RootProvider } from 'fumadocs-ui/provider'
import { Geist, Geist_Mono } from 'next/font/google'
import 'fumadocs-ui/style.css'
import './globals.css'

const geist = Geist({
  subsets: ['latin'],
  variable: '--font-geist',
  display: 'swap',
})

const geistMono = Geist_Mono({
  subsets: ['latin'],
  variable: '--font-geist-mono',
  display: 'swap',
})

export const metadata = {
  title: {
    default: 'Lamport OTS - Quantum-Resistant Signatures',
    template: '%s | Lamport OTS',
  },
  description: 'Production-ready Lamport One-Time Signatures for Solidity and Go. Quantum-resistant digital signatures using only hash functions.',
  keywords: ['Lamport', 'one-time signatures', 'quantum-resistant', 'post-quantum', 'cryptography', 'Solidity', 'EVM', 'Lux Network'],
  authors: [{ name: 'Lux Network' }],
  metadataBase: new URL('https://lamport.lux.network'),
  icons: {
    icon: '/favicon.svg',
    apple: '/favicon.svg',
  },
  openGraph: {
    title: 'Lamport OTS - Quantum-Resistant Signatures',
    description: 'Production-ready Lamport One-Time Signatures for Solidity and Go. Quantum-resistant digital signatures using only hash functions.',
    type: 'website',
    siteName: 'Lamport OTS',
    images: [
      {
        url: '/og.png',
        width: 1200,
        height: 630,
        alt: 'Lamport OTS - Quantum-Resistant Signatures for Lux Network',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Lamport OTS - Quantum-Resistant Signatures',
    description: 'Production-ready Lamport One-Time Signatures for Solidity and Go.',
    images: ['/og.png'],
  },
}

export default function RootLayout({
  children
}: {
  children: ReactNode
}) {
  return (
    <html lang="en" className={`${geist.variable} ${geistMono.variable}`} suppressHydrationWarning>
      <head>
        {/* Prevent flash - respect system preference */}
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                if (prefersDark) {
                  document.documentElement.classList.add('dark');
                }
              })();
            `,
          }}
        />
      </head>
      <body className="min-h-screen bg-background font-sans antialiased">
        <RootProvider
          theme={{
            enabled: true,
            defaultTheme: 'system',
          }}
        >
          <div className="relative flex min-h-screen flex-col">
            {children}
          </div>
        </RootProvider>
      </body>
    </html>
  )
}
