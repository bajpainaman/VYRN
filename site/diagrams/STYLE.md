# VYRN diagram style: hand-drawn order tickets

Every spec diagram on the site is redrawn in Excalidraw, in addition to its ASCII original (the spec
requires ASCII; the drawing never replaces it). Read the Excalidraw skill first:
`/Users/namanbajpai/plankbook/.claude/skills/excalidraw-diagram/SKILL.md`, then its
`references/color-palette.md` (VYRN colours, the only colours allowed) and `references/element-templates.md`.

## The look: fun, but never wrong

- `roughness: 1` on every shape, line and arrow. Hand-drawn, like a clerk sketching on the back of a ticket.
- Labels, titles and annotations: `fontFamily: 5` (Excalifont, handwriting).
- Bytes, field names, code identifiers, spec IDs and numbers with units: `fontFamily: 3` (mono), so they stay exact.
- Rectangles may use `"roundness": {"type": 3}`. Fill `solid`; `hachure` is allowed for the pink data-tier and replica fills.
- Every diagram opens with a **title that states its argument as a sentence** (fontSize 26–30, ink), e.g.
  "The cut replaces the sequencer", not "Cut core diagram".
- Add one or two **violet margin notes** (`#5A2D91`, Excalifont, 16–20) with a curved arrow pointing at the
  thing they explain: "only ~3% get here", "this is the whole 1 µs". They make it fun. They must be true:
  take the fact from the ASCII or from the spec text around it. Never a joke that misstates a number.
- Colour carries meaning, exactly as the palette file says: canary = hot path / sequencer, pink = data tier,
  replicas, anything fed by the copy, violet = certificates, votes, finality, stamps, timings, white = clients,
  external. Blue and red mean BUY and SELL only.
- Use the skill's patterns: fan-out, convergence, timeline, assembly line, side-by-side. Do not draw a grid of
  equal boxes. Free-floating text over containers where a box adds nothing.

## Truth rules (hard)

- Every component, arrow, label and number must exist in the ASCII original or the paragraph around it in
  `/Users/namanbajpai/plankbook/site/content/<file>`. Nothing invented. Keep spec names verbatim
  (`vyrn-seq`, `LaneCut[l]`, `R_step`).
- If the ASCII shows a table of numbers rather than a structure (rare), redraw it as the simplest visual
  that keeps every number (a timeline, a bar), not a fancier table.
- Keep the direction of every arrow.

## Size (it must read on the site)

- The docs column is about 880 px wide. Keep the canvas **width ≤ 1200 units** and every label
  **fontSize ≥ 16** (mono evidence ≥ 14). Tall is fine; wide is not.
- Leave about 40 units of margin inside the canvas edges.

## Files you own (write nothing else)

For each diagram, `NN` = its `asciiIndex` from `diagrams/inventory.json` when you draw it, zero-padded to 2
(the file name only; it is not renamed when the block later moves):

- Source: `/Users/namanbajpai/plankbook/site/diagrams/<slug>-NN.excalidraw`
- Export: `/Users/namanbajpai/plankbook/site/public/diagrams/<slug>-NN.svg`
- Preview PNGs only under your own scratch dir: `/tmp/vyrn-diagrams/<your-worker-name>/`
- Your manifest: `/Users/namanbajpai/plankbook/site/diagrams/manifest/<your-worker-name>.json`, a JSON array of
  `{ "slug": "<slug>", "ascii": "<the block's hash from inventory.json>", "file": "<slug>-NN", "width": <viewBox w>, "height": <viewBox h>, "alt": "<2–4 sentence description of what the diagram shows and argues>" }`.
  Read width and height from the SVG's `viewBox`.

Do not edit the spec, `content/`, any `.tsx`/`.ts`/`.css` file, or another worker's files.

## Render loop (mandatory, per diagram)

```bash
cd /Users/namanbajpai/plankbook/.claude/skills/excalidraw-diagram/references && \
  uv run python render_excalidraw.py /Users/namanbajpai/plankbook/site/diagrams/<slug>-NN.excalidraw \
  -o /tmp/vyrn-diagrams/<worker>/<slug>-NN.png --svg /Users/namanbajpai/plankbook/site/public/diagrams/<slug>-NN.svg
```

Then open the PNG with your image-reading tool and fix overlaps, clipped text, stray arrows and lopsided
spacing, then render again. Two or three passes is normal. A diagram you never looked at is not done.

## When a spec edit adds or moves an ASCII block

The `site-diagrams` CI job fails when `site/content/spec` or `diagrams/inventory.json` is stale. Regenerate
both from the repository root and commit the result:

```bash
(cd site && node scripts/sync-spec.mjs && node scripts/diagram-inventory.mjs)
```

A figure is keyed by the `hash` of its block's text (`ascii` in `diagrams/manifest/*.json`), so a block that
only moves keeps its figure and needs nothing more. If you change the text of a block that has a figure, the
figure no longer shows and `(cd site && pnpm exec vitest run lib/diagrams.test.ts)` fails. Check the drawing
still matches the new ASCII (redraw it if not), then set its `ascii` to the block's new `hash`.
