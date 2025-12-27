# Upstream Template

This docs site is based on `@luxfi/docs-template`.

## Pulling Upstream Changes

To pull layout/style improvements from the template:

```bash
# Add upstream remote (one-time)
cd ~/work/lux/docs-template
git remote add origin git@github.com:luxfi/docs-template.git 2>/dev/null || true

# In lamport repo, pull specific files from template
cd ~/work/lux/lamport

# Copy layout improvements
cp ~/work/lux/docs-template/app/docs/layout.tsx docs/app/docs/layout.tsx
cp ~/work/lux/docs-template/app/globals.css docs/app/globals.css
cp ~/work/lux/docs-template/components/logo.tsx docs/components/logo.tsx

# Re-apply Lamport-specific config (edit DOCS_CONFIG in layout.tsx)
```

## Template Structure

Files from template (can be updated):
- `app/layout.tsx` - Base layout (update SITE_CONFIG after copy)
- `app/docs/layout.tsx` - Sidebar layout (update DOCS_CONFIG after copy)
- `app/globals.css` - Styles
- `components/logo.tsx` - Logo component
- `lib/source.ts` - Content source

Files specific to Lamport (don't overwrite):
- `content/docs/*.md` - Documentation content
- `content/docs/meta.json` - Sidebar structure
- `public/og.png` - OG image
