import { DocsLayout } from 'fumadocs-ui/layouts/docs'
import type { ReactNode } from 'react'
import { ExternalLink, Github } from 'lucide-react'
import { LogoWithText } from '@/components/logo'
import { source } from '@/lib/source'

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.pageTree}
      nav={{
        title: <LogoWithText size={24} />,
      }}
      sidebar={{
        defaultOpenLevel: 1,
        footer: (
          <div className="flex flex-col gap-2 p-4 text-xs border-t border-fd-border">
            <a
              href="https://github.com/luxfi/lamport"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-fd-muted-foreground hover:text-fd-foreground transition-colors"
            >
              <Github className="size-4" />
              View on GitHub
            </a>
            <a
              href="https://lps.lux.network/docs/lp-4105"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-fd-muted-foreground hover:text-fd-foreground transition-colors"
            >
              <ExternalLink className="size-4" />
              LP-4105 Specification
            </a>
          </div>
        ),
      }}
      links={[
        {
          text: 'GitHub',
          url: 'https://github.com/luxfi/lamport',
          icon: <Github className="size-4" />,
          external: true,
        },
      ]}
    >
      {children}
    </DocsLayout>
  )
}
