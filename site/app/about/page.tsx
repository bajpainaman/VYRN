import type { Metadata } from "next";
import Link from "next/link";
import { PlainPage } from "@/components/PlainPage";
import { LICENSE_URL, REPO_URL, SPEC_DATE, SPEC_DRAFT } from "@/lib/site";

export const metadata: Metadata = {
  title: "About",
  description: "What VYRN is, what state it is in, and who publishes it.",
  alternates: { canonical: "/about" },
};

export default function AboutPage() {
  return (
    <PlainPage title="About VYRN">
      <p>
        VYRN is an exchange design with one central limit order book per instrument. It aims to meet five requirements at
        once: a fill at most 1 µs after an order&apos;s first bit reaches the exchange NIC, 1B inbound messages a second on one
        book, BFT finality within 10 ms, a book that moves TYO → LDN → NYC every 8 hours, and an optional on-chain mode with 5
        validators. It uses x86 CPUs and off-the-shelf NICs, with no FPGA.
      </p>
      <h2>Where it stands</h2>
      <p>
        VYRN is a design and a specification ({SPEC_DRAFT}, {SPEC_DATE}), not a running venue. Every performance figure on this
        site is a design budget. No benchmark has run yet; the five week-one tests in <Link href="/docs/design">DESIGN.md §9</Link>{" "}
        are the first measurements the design commits to.
      </p>
      <h2>What this site holds</h2>
      <p>
        <Link href="/docs/design">DESIGN.md</Link>, the design in one document, and the fifteen spec chapters from{" "}
        <Link href="/docs/00-index">00 Index</Link> to <Link href="/docs/14-envelope">14 Envelope</Link>. The site renders them from
        the same Markdown that lives in the <a href={REPO_URL}>source repository</a>, so the two cannot drift. Agents can read
        the same content as Markdown or through the <Link href="/developers">read-only API</Link>.
      </p>
      <h2>Who publishes it</h2>
      <p>
        VYRN is published by bajpainaman on GitHub under the <a href={LICENSE_URL}>VYRN Research and Education License 1.0</a>:
        source-available, free for research and education, with written permission needed for commercial or production use and
        for financial institutions or government bodies. See <Link href="/contact">Contact</Link> for how to reach the project.
      </p>
    </PlainPage>
  );
}
