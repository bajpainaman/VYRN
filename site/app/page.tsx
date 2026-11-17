import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import { Arrow } from "@/components/Arrow";
import { HomeNow } from "@/components/HomeNow";
import { JsonLd } from "@/components/JsonLd";
import { TrackedLink } from "@/components/TrackedLink";
import { SITE_ORIGIN, SUMMARY } from "@/lib/agent";
import { SiteFooter } from "@/components/SiteFooter";
import { Ticket } from "@/components/Ticket";
import {
  designHref,
  getAsciiAfter,
  getComparison,
  getGlossary,
  getGrilling,
  getHandoffs,
  getMessageShares,
  getSixLines,
  getWeekOneTests,
  type ShareRow,
} from "@/lib/design";
import { renderNodes } from "@/lib/render";
import { CONTACT_EMAIL, LICENSE_REQUEST_URL, LICENSE_URL, REPO_URL } from "@/lib/site";

export const metadata: Metadata = { alternates: { canonical: "/" } };

type Ply = "canary" | "white" | "pink";

const PLY_BG: Record<Ply, string> = { canary: "bg-canary", white: "bg-ply", pink: "bg-pink" };

/**
 * Spec HTML rendered on the server from the spec's own Markdown. remark-rehype drops raw HTML from
 * the source, so the string holds only elements the renderer built.
 */
function Prose({ html, className = "" }: { html: string; className?: string }) {
  return <div className={`prose-spec ${className}`} dangerouslySetInnerHTML={{ __html: html }} />;
}

/** One ply of the ticket: same rules, same punched binding edge as the hero, its source in the corner. */
function Part({
  id,
  title,
  source,
  ply = "canary",
  stamp,
  children,
}: {
  id: string;
  title: ReactNode;
  source: { href: string; label: string };
  ply?: Ply;
  stamp?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} className={`ticket relative border-2 border-ink ${PLY_BG[ply]}`}>
      <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3 border-b-2 border-ink pb-4 pl-7 pr-5 pt-6 sm:pl-9 sm:pr-8">
        <h2 id={`${id}-title`} className="display max-w-[22ch] text-[clamp(2rem,4vw,3.4rem)]">
          {title}
        </h2>
        <div className="flex items-end gap-5 pb-1">
          {stamp}
          <Link href={source.href} className="caption text-ink-soft">
            {source.label}
          </Link>
        </div>
      </header>
      {children}
    </section>
  );
}

function Tear() {
  return <div className="perf my-12 sm:my-16" role="presentation" />;
}

/** A struck stamp with a hand-set angle, so a row of them never looks machine-aligned. */
function Struck({ label, children, rot, size = "text-[17px]" }: { label?: string; children: ReactNode; rot: number; size?: string }) {
  return (
    <span className={`stamp ${size}`} style={{ rotate: `${rot}deg` }}>
      {label && <span className="stamp-label">{label}</span>}
      {children}
    </span>
  );
}

// Angles a clerk's hand gives a row of stamps: irregular, never alternating.
const STAMP_ANGLES = [-4, 2.5, -1.5, 3.5, -3, 1, -2.5, 4] as const;

// Where each of the six lines is worked out in full. The lines themselves come from DESIGN.md §0.
const LINE_SOURCES: readonly (readonly [string, string])[][] = [
  [["DESIGN §3", "3."], ["05 Engine", "/docs/05-engine"]],
  [["DESIGN §3", "3."], ["05 Engine", "/docs/05-engine"]],
  [["DESIGN §5", "5."], ["07 Replication", "/docs/07-replication"]],
  [["DESIGN §5", "5."], ["07 Replication", "/docs/07-replication"]],
  [["DESIGN §6", "6."], ["08 Epochs", "/docs/08-epochs"]],
  [["DESIGN §8", "8."], ["11 Build", "/docs/11-build"]],
];

async function resolveSource([label, target]: readonly [string, string]) {
  return { label, href: target.startsWith("/") ? target : await designHref(target) };
}

async function SixLines() {
  const lines = await getSixLines();
  const rendered = await Promise.all(lines.map((line) => renderNodes([line.body], "design")));
  const sources = await Promise.all(LINE_SOURCES.map((pair) => Promise.all(pair.map(resolveSource))));
  return (
    <ol className="grid gap-[2px] bg-ink">
      {lines.map((line, i) => (
        <li key={line.lead} className="grid grid-cols-1 gap-x-8 gap-y-3 bg-canary py-6 pl-7 pr-5 sm:pl-9 sm:pr-8 md:grid-cols-[64px_minmax(0,1fr)_200px]">
          <span className="text-[44px] font-black leading-none [font-stretch:75%]" aria-hidden>
            {i + 1}
          </span>
          <div>
            <h3 className="text-[clamp(1.35rem,2.2vw,1.85rem)] font-black leading-[1.05] [font-stretch:80%] [text-wrap:balance]">
              {line.lead}
            </h3>
            <Prose html={rendered[i]?.html ?? ""} className="mt-2.5 [&_p]:m-0" />
          </div>
          <ul className="flex flex-wrap content-start gap-2 md:flex-col md:items-start" aria-label="Worked out in">
            {sources[i]?.map((s) => (
              <li key={s.label}>
                <Link href={s.href} className="caption inline-block border-2 border-ink px-2.5 py-1.5 no-underline hover:bg-slab hover:text-on-slab">
                  {s.label}
                </Link>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ol>
  );
}

const GLOSSARY_TERMS = ["home", "epoch", "sequencer", "lane", "cut", "BBO core", "data tier", "replica", "block", "certificate", "mode"] as const;

async function Words() {
  const entries = await getGlossary(GLOSSARY_TERMS);
  const rendered = await Promise.all(entries.map((e) => renderNodes([e.meaning], "01-conventions")));
  return (
    <dl className="grid grid-cols-1 gap-[2px] bg-ink md:grid-cols-2">
      <div className="bg-ply py-4 pl-7 pr-5 sm:pl-9 sm:pr-8">
        <dt className="data text-[15px] font-semibold text-stamp">ply 1 · ply 2</dt>
        <dd className="mt-1 text-[16px] leading-[1.55]">
          This page&apos;s name for the two copies of every packet: ply 1 goes to the sequencer, ply 2 to a data node
          (DESIGN §0, line 3).
        </dd>
      </div>
      {entries.map((entry, i) => (
        <div key={entry.term} className="bg-ply py-4 pl-7 pr-5 sm:pl-9 sm:pr-8">
          <dt className="data text-[15px] font-semibold text-stamp">{entry.term}</dt>
          <dd>
            <Prose html={rendered[i]?.html ?? ""} className="mt-1 [&_p]:m-0 [&_p]:text-[16px]" />
          </dd>
        </div>
      ))}
      <div className="bg-ply py-4 pl-7 pr-5 sm:pl-9 sm:pr-8 md:col-span-2">
        <Link href="/docs/01-conventions#1-words" className="caption text-ink-soft">
          All terms: 01 §1, Words
        </Link>
      </div>
    </dl>
  );
}

const SHARE_STYLE: Record<"lane" | "bbo", string> = {
  lane: "border-[1.5px] border-ink/55",
  bbo: "bg-ink",
};

function shareKind(row: ShareRow): "lane" | "bbo" {
  return /bbo/i.test(row.handledBy) ? "bbo" : "lane";
}

async function MessageStrip() {
  const shares = await getMessageShares();
  const master = await getAsciiAfter("00-index", "Master diagram");
  const diagram = await renderNodes([master.code], "00-index", { asciiStart: master.asciiIndex });
  const cells = shares.flatMap((row) => Array.from({ length: Math.round(row.share) }, () => row));
  const toBbo = shares.filter((r) => shareKind(r) === "bbo").reduce((s, r) => s + r.share, 0);
  return (
    <div>
      <div className="grid grid-cols-1 gap-8 py-7 pl-7 pr-5 sm:pl-9 sm:pr-8 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div>
          <div
            className="grid grid-cols-[repeat(20,minmax(0,1fr))] gap-[5px] sm:grid-cols-[repeat(25,minmax(0,1fr))]"
            role="img"
            aria-label={`100 messages by type: ${shares.map((r) => `${r.share} ${r.message}`).join(", ")}. ${toBbo} reach the BBO core.`}
          >
            {cells.map((row, i) => (
              <span key={i} className={`aspect-square ${SHARE_STYLE[shareKind(row)]}`} />
            ))}
          </div>
          <p className="mt-4 max-w-[60ch] text-[15px] text-ink-mute">
            100 messages in the design mix. Outlined squares stay on the lane core that owns the account. Inked squares change the
            best bid or offer, so they go to the one BBO core.
          </p>
        </div>
        <table className="w-full self-start border-2 border-ink text-[15px]">
          <thead>
            <tr className="border-b-2 border-ink text-left">
              <th className="caption px-3 py-2">Message</th>
              <th className="caption px-3 py-2">Goes to</th>
              <th className="caption px-3 py-2 text-right">Share</th>
            </tr>
          </thead>
          <tbody>
            {shares.map((row) => (
              <tr key={row.message} className="border-b border-ink/25 last:border-b-0">
                <td className="px-3 py-2">
                  <span className={`mr-2 inline-block size-3 align-[-1px] ${SHARE_STYLE[shareKind(row)]}`} aria-hidden />
                  {row.message.replace(/\s*\(.*\)$/, "")}
                </td>
                <td className="px-3 py-2">{row.handledBy}</td>
                <td className="data px-3 py-2 text-right">~{row.share}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="border-t-2 border-ink py-6 pl-7 pr-5 sm:pl-9 sm:pr-8">
        <h3 className="caption mb-3">Master diagram · spec 00</h3>
        <Prose html={diagram.html} className="[&_.ascii-wrap]:m-0 [&_.diagram]:mb-0" />
      </div>
    </div>
  );
}

async function RateCard() {
  const rows = await getComparison();
  return (
    <div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left">
          <thead>
            <tr className="border-b-2 border-ink">
              <th className="caption w-[22%] py-3 pl-7 pr-5 sm:pl-9">Axis</th>
              <th className="caption px-5 py-3">Best in production · public figures</th>
              <th className="caption px-5 py-3 sm:pr-8">This spec · budget</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.axis} className="border-b border-ink/25 align-top last:border-b-0">
                <th scope="row" className="py-4 pl-7 pr-5 text-[16px] font-bold sm:pl-9">{row.axis}</th>
                <td className="px-5 py-4 text-[16px]">{row.best}</td>
                <td className="px-5 py-4 text-[clamp(1.2rem,2vw,1.6rem)] font-black leading-tight [font-stretch:80%] sm:pr-8">{row.spec}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="border-t-2 border-ink py-3 pl-7 pr-5 text-[14px] text-ink-soft sm:pl-9 sm:pr-8">
        Public figures as DESIGN.md §1 states them; the design document does not attach sources to them yet.
      </p>
    </div>
  );
}

async function FollowTheSun() {
  const handoffs = await getHandoffs();
  const boundaries = await getAsciiAfter("08-epochs", "2.1 Boundaries");
  const schedule = await renderNodes([boundaries.code], "08-epochs", { asciiStart: boundaries.asciiIndex });
  return (
    <div className="grid grid-cols-1 gap-[2px] bg-ink lg:grid-cols-2">
      <div className="bg-pink py-7 pl-7 pr-5 sm:pl-9 sm:pr-8">
        <p className="max-w-[52ch] text-[18px] leading-[1.5]">
          The same operators run nodes in every home. The book moves by certificate, not by vote. A handoff costs one WAN one-way
          latency, and an opening auction serves that gap.
        </p>
        <div className="mt-6">
          <HomeNow />
        </div>
      </div>
      <div className="bg-pink py-7 pl-7 pr-5 sm:pl-9 sm:pr-8">
        <table className="w-full border-2 border-ink bg-pink text-[15px]">
          <thead>
            <tr className="border-b-2 border-ink text-left">
              <th className="caption px-3 py-2">Handoff</th>
              <th className="caption px-3 py-2 text-right">WAN one-way</th>
              <th className="caption px-3 py-2 text-right">No-fill window</th>
            </tr>
          </thead>
          <tbody>
            {handoffs.map((h) => (
              <tr key={h.handoff} className="border-b border-ink/30 last:border-b-0">
                <td className="px-3 py-2.5 font-bold">{h.handoff}</td>
                <td className="data px-3 py-2.5 text-right">{h.wan}</td>
                <td className="data px-3 py-2.5 text-right">{h.window}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-[14px] text-ink-soft">Light sets this floor, not the design. Orders in the window get a 1 µs ack that they joined the auction.</p>
      </div>
      <div className="bg-pink py-7 pl-7 pr-5 sm:pl-9 sm:pr-8 lg:col-span-2">
        <h3 className="caption mb-3">The schedule · 08 §2.1</h3>
        <Prose html={schedule.html} className="mx-auto max-w-[1100px] [&_.ascii-wrap]:m-0 [&_.diagram]:mb-0" />
      </div>
    </div>
  );
}

async function WeekOne() {
  const tests = await getWeekOneTests();
  const rendered = await Promise.all(
    tests.map((t) => renderNodes([{ type: "paragraph", children: [{ type: "text", value: t.pass }] }], "design")),
  );
  return (
    <ol className="grid gap-[2px] bg-ink">
      {tests.map((t, i) => (
        <li key={t.id} className="relative grid grid-cols-1 gap-x-8 gap-y-2 bg-canary py-5 pl-7 pr-5 sm:pl-9 sm:pr-8 md:grid-cols-[64px_minmax(0,1fr)_minmax(0,1fr)_150px]">
          <span className="text-[40px] font-black leading-none [font-stretch:75%]">{t.id}</span>
          <p className="text-[16px] leading-[1.5]">{t.test}</p>
          <div className="text-[16px] leading-[1.5]">
            <span className="caption mb-1 block text-ink-soft">Passes if</span>
            <Prose html={rendered[i]?.html ?? ""} className="[&_p]:m-0 [&_p]:text-[16px]" />
          </div>
          <div className="flex items-start md:justify-end">
            <Struck rot={STAMP_ANGLES[i % STAMP_ANGLES.length]!}>Not yet run</Struck>
          </div>
        </li>
      ))}
    </ol>
  );
}

async function Grilling() {
  const items = await getGrilling();
  const rendered = await Promise.all(items.map((item) => renderNodes([item.body], "design")));
  return (
    <dl className="grid gap-[2px] bg-ink">
      {items.map((item, i) => (
        <div key={item.lead} className="grid grid-cols-1 gap-x-10 gap-y-2 bg-ply py-5 pl-7 pr-5 sm:pl-9 sm:pr-8 md:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <dt className="text-[clamp(1.15rem,1.8vw,1.45rem)] font-black leading-[1.1] [font-stretch:80%] [text-wrap:balance]">
            {item.lead}
          </dt>
          <dd>
            <Prose html={rendered[i]?.html ?? ""} className="[&_p]:m-0" />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** The routing slip that closes the ticket: one inked action, three plain ones, and the license terms. */
function Close() {
  return (
    <section id="license" aria-labelledby="license-title" data-surface="ink" className="border-2 border-ink bg-well text-on-well">
      <div className="grid grid-cols-1 items-start gap-8 px-5 py-8 sm:px-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div>
          <h2 id="license-title" className="display text-[clamp(1.8rem,3.2vw,2.6rem)]">
            Source-available. Read it freely.
          </h2>
          <p className="mt-3 max-w-[56ch] text-[15.5px] leading-[1.55] text-on-well/90">
            Research and education are free. Commercial or production use, and any use by a financial institution or a government
            body, needs written permission first, even for testing. <a href={LICENSE_URL}>Read the license</a> for its complete
            terms.
          </p>
          <p className="mt-3 max-w-[56ch] text-[14px] leading-[1.5] text-on-well/80">
            License requests are public GitHub issues: leave out anything confidential. Opening one does not grant permission.
            {CONTACT_EMAIL && (
              <>
                {" "}For a private conversation, write to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
              </>
            )}
          </p>
        </div>
        <nav aria-label="Next steps" className="grid grid-cols-1 gap-[2px] border-2 border-on-well bg-on-well sm:grid-cols-2">
          <TrackedLink href="/docs/design" event="route_click" eventProps={{ to: "design", from: "close" }} className="routebox inverse primary sm:col-span-2">
            <span className="box"><Arrow /></span>
            <span>Read the design<small>DESIGN.md, the answer in one document</small></span>
          </TrackedLink>
          <TrackedLink href="/docs/00-index" event="route_click" eventProps={{ to: "spec", from: "close" }} className="routebox inverse">
            <span className="box"><Arrow /></span>
            <span>Read the spec<small>Chapters 00–14</small></span>
          </TrackedLink>
          <TrackedLink href={REPO_URL} event="route_click" eventProps={{ to: "github", from: "close" }} className="routebox inverse">
            <span className="box"><Arrow /></span>
            <span>GitHub<small>bajpainaman/VYRN</small></span>
          </TrackedLink>
          <TrackedLink href={LICENSE_REQUEST_URL} event="route_click" eventProps={{ to: "license_request", from: "close" }} className="routebox inverse sm:col-span-2">
            <span className="box"><Arrow /></span>
            <span>Request a license<small>Opens the public request form</small></span>
          </TrackedLink>
        </nav>
      </div>
    </section>
  );
}

export default async function Home() {
  const [d0, d1, d3, d9, d10] = await Promise.all(["0.", "1.", "3.", "9.", "10."].map(designHref));
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": `${SITE_ORIGIN}/#org`,
        name: "VYRN",
        url: SITE_ORIGIN,
        logo: `${SITE_ORIGIN}/icon.svg`,
        description: SUMMARY,
        sameAs: [REPO_URL],
        contactPoint: [
          { "@type": "ContactPoint", contactType: "licensing", url: LICENSE_REQUEST_URL, availableLanguage: "en" },
          { "@type": "ContactPoint", contactType: "technical support", url: `${REPO_URL}/issues`, availableLanguage: "en" },
          { "@type": "ContactPoint", contactType: "security", url: `${REPO_URL}/security/advisories/new`, availableLanguage: "en" },
        ],
        knowsAbout: ["exchange design", "central limit order book", "matching engine", "low-latency trading", "BFT consensus", "Simplex consensus"],
      },
      {
        "@type": "WebSite",
        "@id": `${SITE_ORIGIN}/#site`,
        url: SITE_ORIGIN,
        name: "VYRN: a 1 µs exchange design",
        description: SUMMARY,
        publisher: { "@id": `${SITE_ORIGIN}/#org` },
        inLanguage: "en",
      },
      {
        "@type": "TechArticle",
        headline: "VYRN: filled within 1 µs of the first bit",
        description: SUMMARY,
        url: SITE_ORIGIN,
        keywords: "exchange design, central limit order book, matching engine, 1 µs fills, BFT finality, follow the sun",
        isPartOf: { "@id": `${SITE_ORIGIN}/#site` },
        author: { "@id": `${SITE_ORIGIN}/#org` },
        license: LICENSE_URL,
      },
    ],
  };
  return (
    <>
      <JsonLd data={jsonLd} />
      <main id="main" className="flex-1">
        <Ticket />
        <div className="mx-auto w-full max-w-[1440px] px-4 pb-16 sm:px-8">
          <Part id="six-lines" title="The answer in six lines." source={{ href: d0!, label: "DESIGN.md §0" }}>
            <SixLines />
          </Part>
          <Tear />
          <Part id="words" title="Words on this ticket." source={{ href: "/docs/01-conventions#1-words", label: "01 §1" }} ply="white">
            <Words />
          </Part>
          <Tear />
          <Part id="the-book" title="Only 3 in 100 messages reach the one sequential core." source={{ href: d3!, label: "DESIGN.md §3" }} ply="white">
            <MessageStrip />
          </Part>
          <Tear />
          <Part
            id="state-of-the-art"
            title="Budgeted past the state of the art on every axis at once."
            source={{ href: d1!, label: "DESIGN.md §1" }}
            stamp={<Struck label="Every figure" rot={-3} size="text-[16px]">Budget</Struck>}
          >
            <RateCard />
          </Part>
          <Tear />
          <Part id="follow-the-sun" title="The book follows the sun." source={{ href: "/docs/08-epochs", label: "Spec 08 · Epochs" }} ply="pink">
            <FollowTheSun />
          </Part>
          <Tear />
          <Part id="week-one" title="Five tests settle it in week one." source={{ href: d9!, label: "DESIGN.md §9" }}>
            <WeekOne />
          </Part>
          <Tear />
          <Part id="grilling" title="The grilling, answered." source={{ href: d10!, label: "DESIGN.md §10" }} ply="white">
            <Grilling />
          </Part>
          <Tear />
          <Close />
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
