# VYRN site

The landing page (`/`) and the spec reader (`/docs/<chapter>`) for VYRN. Next.js 16, Tailwind 4, pnpm.

## Content

The site renders `content/DESIGN.md` and `content/spec/*.md`. These are copies of the spec repo, committed
here because Vercel builds without access to it. Refresh them before each deploy:

```bash
pnpm sync-spec                       # copies from the parent folder
SPEC_SOURCE=~/VYRN pnpm sync-spec    # or from the canonical repo
```

The landing page reads its sections from `DESIGN.md` at build time (§0, §1, §3, §6, §9, §10). If a heading or
table it reads moves, the build fails and names what is missing.

## Commands

```bash
pnpm dev          # dev server
pnpm build        # production build
pnpm lint
pnpm typecheck
```

## Environment

| Variable | Purpose |
|---|---|
| `NEXT_PUBLIC_CONTACT_EMAIL` | Public contact address. Unset hides the contact route. |
| `NEXT_PUBLIC_SITE_URL` | Canonical URL for metadata. Defaults to `http://localhost:3000`. |

## Deploy

With the Vercel CLI, from this folder:

```bash
vercel            # preview
vercel --prod     # production
```
