---
name: VYRN
description: A paper order ticket that a time clock stamps, set at 1 µs.
colors:
  canary: "#f2d447"
  canary-shade: "#e6c534"
  pink: "#f4b7c2"
  ply: "#fcfcf9"
  figure-white: "#ffffff"
  ink: "#191b26"
  ink-soft: "#4a4318"
  ink-mute: "#565a6b"
  buy: "#1e4db7"
  sell: "#a3161d"
  stamp: "#5a2d91"
  stamp-wash: "#ede5f6"
  code-text: "#eceaf2"
typography:
  display:
    fontFamily: "Archivo, sans-serif"
    fontSize: "clamp(3.1rem, 6.4vw, 5.75rem)"
    fontWeight: 900
    lineHeight: 0.92
    letterSpacing: "-0.01em"
    fontVariation: "'wdth' 75"
  headline:
    fontFamily: "Archivo, sans-serif"
    fontSize: "clamp(2rem, 4vw, 3.4rem)"
    fontWeight: 900
    lineHeight: 0.92
    letterSpacing: "-0.01em"
    fontVariation: "'wdth' 75"
  title:
    fontFamily: "Archivo, sans-serif"
    fontSize: "clamp(1.6rem, 2.4vw, 2.05rem)"
    fontWeight: 900
    lineHeight: 1.05
    fontVariation: "'wdth' 88"
  subtitle:
    fontFamily: "Archivo, sans-serif"
    fontSize: "1.2rem"
    fontWeight: 800
    lineHeight: 1.2
    fontVariation: "'wdth' 100"
  body:
    fontFamily: "Archivo, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "'tnum' 1"
  body-spec:
    fontFamily: "Archivo, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.62
  route:
    fontFamily: "Archivo, sans-serif"
    fontSize: "19px"
    fontWeight: 800
    lineHeight: 1.15
    fontVariation: "'wdth' 112"
  label:
    fontFamily: "Archivo, sans-serif"
    fontSize: "11px"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.1em"
    fontVariation: "'wdth' 125"
  data:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "clamp(17px, 1.6vw, 24px)"
    fontWeight: 600
    lineHeight: 1.25
    fontFeature: "'tnum' 1, 'zero' 1"
  grid:
    fontFamily: "Martian Mono, ui-monospace, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.38
    fontFeature: "'liga' 0, 'calt' 0"
  stamp:
    fontFamily: "Doto, Martian Mono, monospace"
    fontSize: "22px"
    fontWeight: 800
    lineHeight: 1.02
rounded:
  none: "0px"
  code: "2px"
spacing:
  cell-y: "14px"
  cell-x: "18px"
  part-x-binding: "36px"
  part-x: "32px"
  gutter-sm: "16px"
  gutter: "32px"
  tear: "64px"
  header: "56px"
components:
  routebox:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    typography: "{typography.route}"
    rounded: "{rounded.none}"
    padding: "18px 20px"
  routebox-hover:
    backgroundColor: "{colors.canary-shade}"
  routebox-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.canary}"
    typography: "{typography.route}"
    rounded: "{rounded.none}"
    padding: "18px 20px"
  routebox-inverse-primary:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    typography: "{typography.route}"
    rounded: "{rounded.none}"
    padding: "18px 20px"
  routebox-docs:
    backgroundColor: "{colors.ply}"
    textColor: "{colors.ink}"
    typography: "{typography.route}"
    padding: "18px 20px"
  field-cell:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    padding: "10px 20px"
  stamp:
    textColor: "{colors.stamp}"
    typography: "{typography.stamp}"
    rounded: "{rounded.none}"
    padding: "8px 14px 9px"
  button-plain:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "8px 12px"
  button-plain-hover:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.canary}"
  input-search:
    backgroundColor: "{colors.ply}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "8px 12px"
  binder-tab:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    padding: "8px 20px"
  binder-tab-active:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.canary}"
  nav-cell:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    height: "{spacing.header}"
    padding: "0 20px"
  spec-table-head:
    backgroundColor: "{colors.canary}"
    textColor: "{colors.ink}"
    padding: "9px 12px"
  code-block:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.code-text}"
    typography: "{typography.grid}"
    padding: "18px 20px"
---

# Design System: VYRN

## Overview

**Creative North Star: "The Order Ticket"**

Every surface is a multi-part paper order ticket that a time clock stamps. The canary top ply is the ground the sequencer sees; the pink carbon is the copy routed to the data tier; the white original ply is where long reading happens. The form is printed in carbon-black ink: 2px rules, labelled cells, perforated tears between parts, a punched binding edge down the left. The page does not decorate the ticket; it is the ticket, and its printed fields carry real content (the 16-byte wire format, spec IDs, budgets).

Density is that of a working form: cells packed edge to edge, separated by rules rather than whitespace, with type doing the hierarchy. Display type is Archivo pulled condensed and black; labels are the same family pulled wide; every number and byte is Martian Mono; only the time clock prints in Doto dot-matrix. Violet is the clock's ribbon and appears only where something was stamped, has a status, or is an identifier you can follow. Motion is mechanical and rare: stamps strike, plies sit offset. Nothing else moves.

The system is flat and square. Depth is the stack of plies, not shadow; corners are never rounded. Numbers always carry their kind (budget, measured, vendor) beside them, because a ticket that misstates a figure is a wrong ticket.

**Key Characteristics:**
- Canary / pink / white plies as the only surfaces; ink as the only stroke.
- 2px ink rules and 2px gap-as-rule grids carve every region into cells.
- Archivo on its width axis: condensed for display, expanded for labels.
- Martian Mono for every figure, byte, ID and field value; tabular, slashed zero.
- Violet stamps in Doto, struck at hand-set angles, for timestamps and statuses.
- Square corners, no elevation beyond the ply stack.
- Spec prose on the white ply at a 58ch measure; ASCII on a true cell grid.

## Colors

A three-ply carbon form in ink, with one ribbon colour and two colours reserved for trade side.

### Primary
- **Canary Top Ply** (canary): the page ground and the default cell fill. Header, footer, binder, ticket body, field cells, routing boxes and table head rows all sit on it.
- **Carbon Ink** (ink): every rule, border, cell gap, and the default text. Also the fill of the inked surfaces (primary routing box, the closing license slip, code blocks, the active binder tab, the live home cell).

### Secondary
- **Time-Clock Violet** (stamp): the ribbon. Stamps and their borders, RX/CUT/FILL/FINAL log labels once struck, the HOME NOW readout, chapter numbers on doc sheets, spec-ID links, § links, the active TOC entry, glossary terms, the focus ring, text selection and the caret.
- **Stamp Wash** (stamp-wash): the faint violet tint a targeted spec-ID table row takes when its anchor is followed.

### Tertiary
- **Buy Blue** (buy) and **Sell Red** (sell): the side of an order. Nothing else.

### Neutral
- **Pink Carbon** (pink): the duplicate ply. The offset copy behind the hero ticket ("Ply 2 · copy → data tier") and parts whose subject is the data tier or what the copy feeds (Follow the sun).
- **White Original** (ply): the reading ply. Doc sheets, search field and results, glossary and grilling parts.
- **Figure White** (figure-white): the field inside table, ASCII and drawn-diagram frames, and the Excalidraw canvas.
- **Canary Shade** (canary-shade): the hover fill for any cell-shaped control on canary; also the scrollbar track.
- **Ink on Canary** (ink-soft): secondary text on canary (ink tinted toward the ply), used for captions, sources, serials, sub-values, and routing-box sublines.
- **Muted Ink** (ink-mute): secondary text on the white ply: figcaptions, blockquotes, list markers, doc meta lines, heading anchors.
- **Code Text** (code-text): body text inside ink code blocks.

### Named Rules
**The Side Rule.** Blue and red mean BUY and SELL and nothing else, on the site and in every diagram. No blue links, no red errors, no red warnings.

**The Ribbon Rule.** Violet marks what the clock printed or what you can follow: stamps, statuses, timings, IDs, § references. It never fills a surface larger than a stamp-wash row, and it is never decoration.

**The Ply Rule.** A part sits on canary, pink or white because of what it is: canary for the hot path and the argument, pink for the copy and the data tier, white for reading and definitions. Do not pick a ply for variety.

## Typography

**Display Font:** Archivo (variable, `wdth` axis), with sans-serif fallback
**Body Font:** Archivo
**Data Font:** Martian Mono, with ui-monospace fallback
**Stamp Font:** Doto (700/800), falling back to Martian Mono

**Character:** one grotesque stretched across its width axis does the whole printed form: squeezed and black for the headline that fills the INSTRUCTIONS field, wide and tracked for printed field captions. Martian Mono fills in the fields; Doto is the time clock's dot-matrix head and prints nothing else.

### Hierarchy
- **Display** (900, clamp(3.1rem, 6.4vw, 5.75rem), 0.92, width 75%): the ticket headline only, balanced, held to about 12ch.
- **Headline** (900, clamp(2rem, 4vw, 3.4rem), width 75%): the title of each ticket part; doc sheet titles use clamp(2.2rem, 4.4vw, 3.8rem) at the same settings. Row leads inside parts step down to width 80%, clamp(1.15–1.35rem … 1.45–1.85rem).
- **Title** (900, clamp(1.6rem, 2.4vw, 2.05rem), 1.05, width 88%): spec h2, always with a 2px rule above it.
- **Subtitle** (800, 1.2rem, 1.2, width 100%): spec h3; h4 is 800 at 1rem.
- **Body** (400, 17px, 1.5, tabular figures): landing copy; hero lede at 19px/1.45.
- **Body Spec** (400, 17px, 1.62): doc prose, held to 58ch.
- **Route** (800, 19px, 1.15, width 112%): routing-box labels; their sublines drop to 500, 13px, width 100%.
- **Label** (700, 11px, 0.1em tracking, uppercase, width 125%): printed field captions. Table heads use 800, 11.5px, 0.06em, width 112%; stamp labels 800, 10px, 0.14em, width 125%.
- **Data** (Martian Mono 600, clamp(17px, 1.6vw, 24px)): field values; sub-values 12px; log 12.5px; IDs 0.86em.
- **Grid** (Martian Mono 400, 13px, 1.38, ligatures off): ASCII diagrams and code.
- **Stamp** (Doto 800, 16–30px, 1.02): stamp faces and the HOME NOW readout (50px).

### Named Rules
**The Width-Axis Rule.** Hierarchy comes from Archivo's width and weight, not from new families. Display condenses (75–88%); labels expand (112–125%). Body stays at 100%.

**The Field Face Rule.** Every number, byte, hex value, timestamp and spec ID is set in Martian Mono with tabular figures and a slashed zero. Prose numbers outside fields still use tabular figures.

**The Clock Head Rule.** Doto prints only what the time clock prints: stamps and the live home. Doto draws "~" like a caret, so an approximation mark inside a stamp is set in Martian Mono.

## Layout

The page is a stack of ticket parts inside a 1440px container with a 16px gutter on phones and 32px from `sm` up. The hero ticket fills most of the first viewport, with the pink copy offset behind it (down 16px, right, rotated 0.4deg). Each later part is its own ruled ticket, separated by a perforated tear with 48px (64px from `sm`) above and below.

Inside a part, regions are cells. Grids use a 2px gap over an ink background, so the gap is the rule (`gap: 2px; background: ink`, children filled with the ply colour). Cells pad 14px × 18px for small fields, and 24px × 20–32px for part rows, with the left padding widened to 28px (36px from `sm`) so content clears the binding edge. The 16-byte message row runs 2, 3, then 6 columns at `sm` and `lg`, with column weights that follow field width.

Docs are a three-column binder from `xl`: 232px tab column (canary), a white sheet with 2px ink rules on both sides, and a 248px "On this sheet" column. At `lg` the TOC column drops and the TOC becomes a sticky collapsible bar under the header; below `lg` the binder tabs become a horizontal scroller with 2px rules between tabs. The site header is 56px, sticky, with nav items as ruled cells on its right edge. Anchors land 16px below the header, or 72px below it where the sticky section bar shows.

### Named Rules
**The Gap-Is-the-Rule Rule.** Do not draw internal borders on grid children. Set a 2px gap on an ink background and let the children's fill reveal the rule. Outer edges take a 2px ink border.

**The 58ch Rule.** Doc paragraphs, lists and blockquotes stop at 58ch (about 72 Archivo characters). Tables, ASCII, code and figures may run the full sheet width and scroll sideways.

## Elevation & Depth

Flat. Depth is the stack of paper plies: the pink copy offset and slightly rotated behind the canary ticket, and the ink surfaces that read as the darkest layer. Two soft ambient shadows exist, each to lift one floating sheet off the form; there are no hard or offset shadows.

### Shadow Vocabulary
- **Ticket lift** (`box-shadow: 0 18px 40px -28px rgba(25,27,38,0.55)`): under the hero ticket only, so it sits on its pink copy.
- **Results sheet** (`box-shadow: 0 14px 30px -18px rgba(25,27,38,0.6)`): under the spec-search results list only.
- **Scroll edge shade** (radial ink gradient at 22% on the scroll edge): inside tables, ASCII and drawn figures that scroll sideways, to say there is more.

### Named Rules
**The Ply Stack Rule.** A surface reads as raised only because another ply sits under it. Do not add shadows to cells, cards or buttons.

## Shapes

Square, ruled and punched. Every corner is 0, except inline code at 2px. Borders are 2px ink (`--rule`); hairlines inside tables are 1px ink at 28%. Two paper details recur: the **punched binding edge**, an 8px column of ink rings every 16px down the left of each ticket part at 70% opacity, above the row fills; and the **perforated tear**, a 2px dashed ink line with a 16px punched notch (canary fill, 2px ink ring) at each end. The only circles in the system are those holes. Stamps are rectangles with a 3px violet border. Routing boxes carry a 24px square with a 2.5px border holding an arrow.

## Components

### Routing Boxes
The ticket's routing slip: a labelled destination, not a checkbox.
- **Shape:** square cell (0), 18px × 20px padding, 14px gap between box and text.
- **Default:** canary fill, ink text, route type with a smaller subline in ink-soft. Sits in a gap-as-rule grid.
- **Primary:** inked (ink fill, canary text), one per slip, always "Read the design". Hover deepens to black.
- **Inverse (on ink surfaces):** ink fill, canary text; its primary inverts back to canary with ink text.
- **Docs:** prev / next chapter boxes on the white ply.
- **Hover / Focus:** fill to canary-shade (160ms ease-out); the arrow nudges 2px right (180ms). Reduced motion removes both transitions.

### Buttons
- **Plain:** 2px ink border, canary fill, 14px 800-weight text at width 112%, 8px × 12px. Hover inks it (ink fill, canary text). Used for "Stamp an order" and the source chips beside each of the six lines.

### Inputs / Fields
- **Search:** 2px ink border on the white ply, 14px text, ink-mute placeholder, 0 radius. Focus drops the default outline for a 2px violet outline. Results open in a white sheet with a 2px border and the results-sheet shadow; ID results print in violet Martian Mono.

### Navigation
- **Site header:** canary, 56px, 2px bottom rule. Wordmark in Archivo 900 at width 125%; nav items are full-height cells with a 2px left rule, 15px bold at width 112%, hover canary-shade.
- **Binder:** chapter tabs on canary, a Martian Mono number in ink-soft before each title; the active tab is inked (ink fill, canary text).
- **On this sheet:** 13.5px list; h2 entries bold, h3 entries ink-soft and indented; the section under the reading line turns violet.

### Stamps (signature)
The time clock's print, in violet Doto with a 3px violet border and a wide-tracked label above the value.
- **Placement:** each stamp has a hand-set angle (between -6deg and 4deg), never alternating, never zero. In the hero they land at fixed registration on the instructions field.
- **Strike:** 260ms, `cubic-bezier(0.2, 1.4, 0.4, 1)`: from 14px above at 118% scale and transparent, overshooting to 97% at 60%, settling at 100%. The angle holds throughout.
- **Sequence:** RX, CUT, FILLED Δ, FINAL n−f, paced for reading (350 / 650 / 650 / 900ms) and labelled as a simulation on spec budgets. The stamp log beside it turns each label violet as its stamp lands.
- **Reduced motion:** no strike; the ticket goes straight to its end state with every stamp visible at its angle.
- **Before hydration:** stamps are hidden when JavaScript is present so the end state never flashes; without JavaScript every stamp shows.

### Field Cells
The wire format printed as form fields: a label caption with its byte range in Martian Mono at right, the value in data type, and the hex beneath in 12px ink-soft. Side values take buy or sell colour.

### Spec Prose
- **Headings:** h2 with a 2px top rule and a mono "#" anchor that shows on hover (always at 60% on touch). 
- **Tables:** framed in a 2px rule on figure white, canary head row with a 2px rule under it, 1px hairlines between cells; ID rows set their first cell in 13px Martian Mono 600 and turn stamp-wash with a violet ID when targeted.
- **Spec IDs and § references:** violet, dotted 1.5px underline that goes solid on hover, never wrapped.
- **Lists:** square bullets in ink-mute; `hr` is the 2px dashed tear line.
- **Code:** ink block, code-text, canary selection.

### ASCII Diagrams and Drawn Figures
- **ASCII:** Martian Mono 13px / 1.38 on figure white in a 2px frame, ligatures and contextual alternates off, no wrapping, tab size 4, scrolling sideways with the edge shade. This is a true cell grid; nothing reflows it.
- **Drawn figure:** where an Excalidraw redrawing exists, the drawing shows first in the same frame, with a caption ("Drawn from the ASCII original below", full-size and source links) and the ASCII original in a disclosure directly under it. On phones the drawing holds 680px and scrolls rather than shrinking.
- **Diagram style:** hand-drawn (roughness 1), Excalifont for labels and titles, mono for bytes, names, IDs and numbers with units. The title states the diagram's argument as a sentence. Fills follow the ply meanings: canary for the hot path and sequencer, pink (solid or hachure) for the data tier and replicas, white for clients and externals, stamp-wash with a violet stroke for certificates, votes and finality. Strokes are ink; violet carries certificate and finality arrows and one or two true margin notes with curved arrows. Canvas at most 1200 units wide, labels at least 16 (mono evidence at least 14).

## Do's and Don'ts

### Do:
- **Do** build every region from cells: 2px ink rules outside, a 2px gap on ink inside.
- **Do** keep each number's kind (budget, measured, vendor) printed beside it.
- **Do** link every spec ID and § reference, in violet with the dotted underline.
- **Do** use a 2px violet focus ring at 3px offset on light plies, and switch it to canary on ink surfaces (violet is 1.8:1 on ink; canary is 11.6:1).
- **Do** give each stamp its own hand-set angle and strike it with the overshoot easing; show its end state under reduced motion.
- **Do** show the ASCII original under every drawn figure, one click away.
- **Do** separate ticket parts with the perforated tear and give each part the punched binding edge.

### Don't:
- **Don't** use blue or red for anything but BUY and SELL.
- **Don't** use violet as a fill, a heading colour or decoration; it marks stamps, statuses, IDs and § links.
- **Don't** round a corner or add a shadow to a cell, card or button.
- **Don't** set Doto for anything the time clock would not print.
- **Don't** wrap, reflow or ligature an ASCII diagram, or replace it with a drawing.
- **Don't** let doc prose run past 58ch.
- **Don't** animate anything other than a stamp strike and the small state transitions on routing boxes and disclosures.
- **Don't** stack a small caption above a headline as an eyebrow; captions label a field or name a source beside it.
