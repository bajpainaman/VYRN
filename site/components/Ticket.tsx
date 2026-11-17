"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { track } from "@vercel/analytics";
import { formatDuration, homeAt, HOMES, type HomeState } from "@/lib/home";
import { LICENSE_REQUEST_URL, REPO_URL } from "@/lib/site";
import { Arrow } from "./Arrow";

type Side = "BUY" | "SELL";
type Order = { serial: number; side: Side; tick: number; qty: number; tag: number; rx: string };

/** 0 = blank ticket, then one phase per stamp: RX, CUT, FILLED, FINAL. */
type Phase = 0 | 1 | 2 | 3 | 4;

// Display pacing only. Each stamp prints the real interval the spec budgets for that step.
const STAMP_DELAYS_MS = [350, 650, 650, 900] as const;
const HOME_REFRESH_MS = 30_000;

const FIRST_ORDER: Order = { serial: 412, side: "BUY", tick: 104250, qty: 300, tag: 0xa41f, rx: "14:32:07.000000412" };

function hex(value: number, width: number): string {
  return `0x${value.toString(16).toUpperCase().padStart(width, "0")}`;
}

/** Byte 1 of a `New` message (01 §6.2): bit 0 = side, bits 1–2 = TIF; IOC is 1. */
function flagsByte(side: Side): number {
  return (side === "SELL" ? 1 : 0) | (1 << 1);
}

function nextOrder(previous: Order): Order {
  const now = new Date();
  const hms = now.toISOString().slice(11, 19);
  const nanos = String(Math.floor(Math.random() * 1e9)).padStart(9, "0");
  return {
    serial: previous.serial + 1,
    side: Math.random() < 0.5 ? "BUY" : "SELL",
    tick: 104000 + Math.floor(Math.random() * 500),
    qty: (1 + Math.floor(Math.random() * 20)) * 50,
    tag: Math.floor(Math.random() * 0xffff),
    rx: `${hms}.${nanos}`,
  };
}

/** Hydration flag without an effect: false on the server render, true once React owns the DOM. */
function subscribeNothing(): () => void {
  return () => {};
}

function prefersReducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function Ticket() {
  const [order, setOrder] = useState<Order>(FIRST_ORDER);
  const [phase, setPhase] = useState<Phase>(4);
  const [home, setHome] = useState<HomeState | null>(null);
  const hydrated = useSyncExternalStore(subscribeNothing, () => true, () => false);
  const timers = useRef<number[]>([]);
  const pad = useRef<HTMLDivElement>(null);

  const run = useCallback((next: Order) => {
    timers.current.forEach((t) => window.clearTimeout(t));
    timers.current = [];
    setOrder(next);
    if (prefersReducedMotion()) {
      setPhase(4);
      return;
    }
    setPhase(0);
    let at = 0;
    STAMP_DELAYS_MS.forEach((delay, i) => {
      at += delay;
      timers.current.push(window.setTimeout(() => setPhase((i + 1) as Phase), at));
    });
  }, []);

  useEffect(() => {
    const pending = timers;
    const start = window.setTimeout(() => run({ ...FIRST_ORDER, rx: nextOrder(FIRST_ORDER).rx }), 0);
    return () => {
      window.clearTimeout(start);
      pending.current.forEach((t) => window.clearTimeout(t));
    };
  }, [run]);

  useEffect(() => {
    const tick = () => setHome(homeAt(new Date()));
    tick();
    const id = window.setInterval(tick, HOME_REFRESH_MS);
    return () => window.clearInterval(id);
  }, []);

  const sideClass = order.side === "BUY" ? "text-buy" : "text-sell";

  return (
    <section aria-labelledby="hero-title" className="relative mx-auto w-full max-w-[1440px] overflow-x-clip px-4 pb-8 pt-5 sm:px-8 sm:pb-10 sm:pt-6">
      <div className="relative pb-8 pr-3 sm:pb-9 sm:pr-5">
      {/* The carbon copy: every packet is also sent to a data node (DESIGN §0, line 3). */}
      <div aria-hidden className="absolute bottom-0 left-5 right-0 top-4 rotate-[0.4deg] bg-pink sm:left-8">
        <span className="caption absolute bottom-2.5 right-4 text-ink">Ply 2 · copy → data tier</span>
      </div>

      <article
        data-phase={phase}
        data-hydrated={hydrated}
        className="ticket relative border-2 border-ink bg-canary shadow-[0_18px_40px_-28px_rgba(25,27,38,0.55)]"
      >
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-1 border-b-2 border-ink px-4 py-3 sm:px-6">
          <span className="text-[18px] font-black tracking-[0.03em] [font-stretch:125%] sm:text-[20px]">VYRN · Order ticket</span>
          <span className="caption data text-ink-soft">
            Serial {String(order.serial).padStart(8, "0")}
            <span className="hidden sm:inline"> · Ply 1 → sequencer</span>
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_360px]">
          <div className="relative border-b-2 border-ink px-4 pb-6 pt-6 sm:px-8 sm:pt-7 lg:border-b-0 lg:border-r-2">
            <h1 id="hero-title" className="display max-w-[12ch] text-[clamp(3.1rem,6.4vw,5.75rem)]">
              Filled within 1&nbsp;µs of the first bit.
            </h1>
            <p className="mt-5 max-w-[58ch] text-[19px] leading-[1.45] xl:max-w-[44ch]">
              One order book per instrument. 1B messages a second on that one book. BFT-final within 10&nbsp;ms. A home
              that moves TYO → LDN → NYC every 8 hours. x86 and off-the-shelf NICs, no FPGA.
            </p>
            <p className="mt-2.5 text-[14px] text-ink-soft xl:max-w-[44ch]">
              Every figure on this page is a design budget unless it says otherwise. No benchmark has run yet.
            </p>

            {/* .routebox sets display itself, so the breakpoint lives on a wrapper. */}
            <div className="mt-5 lg:hidden">
              <Link href="/docs/design" className="routebox primary border-2 border-ink" onClick={() => track("route_click", { to: "design", from: "hero" })}>
                <span className="box"><Arrow /></span>
                <span>Read the design<small>The answer in one document</small></span>
              </Link>
            </div>

            {/* The time clock strikes in a zone of its own: from xl up, the right of the cell, clear of the
                headline and the copy (the copy narrows to 44ch to make room); below xl, a row under the copy. */}
            <div ref={pad} className="mt-5 flex min-h-[64px] flex-wrap items-start gap-3 xl:contents" aria-hidden>
              <Stamp on={phase >= 2} run={order.serial} rot="-6deg" className="hidden md:block xl:absolute xl:right-[21%] xl:top-[31%]" label="Cut" size="text-[20px]">
                <Approx>~150 ns</Approx>
              </Stamp>
              <Stamp on={phase >= 3} run={order.serial} rot="3deg" className="xl:absolute xl:right-[3%] xl:top-[5%]" label="Filled · Δ wire to wire" size="text-[22px] xl:text-[30px]">
                ≤ 965 ns
              </Stamp>
              <Stamp on={phase >= 4} run={order.serial} rot="-2.5deg" className="xl:absolute xl:right-[3%] xl:top-[51%]" label="Final · 3 of 4 signed" size="text-[22px] xl:text-[24px]">
                <Approx>~3 ms</Approx>
              </Stamp>
              <Stamp on={phase >= 1} run={order.serial} rot="-4deg" className="xl:absolute xl:bottom-[6%] xl:right-[3%]" label="RX · NIC hardware timestamp" size="text-[19px] xl:text-[24px]">
                {order.rx}
              </Stamp>
            </div>
          </div>

          <aside aria-label="Home and stamp log" className="grid content-start">
            <div className="border-b-2 border-ink px-5 py-3.5">
              <div className="caption text-ink-soft">Home now</div>
              <div className="mt-1 flex items-end justify-between gap-4">
                <span className="font-[family-name:var(--font-stamp)] text-[50px] font-extrabold leading-none text-stamp" aria-live="polite">
                  {home ? home.home : "···"}
                </span>
                <span className="pb-1 text-right text-[14px] leading-tight">
                  {home ? (
                    <>
                      Hands off to <strong>{home.next}</strong>
                      <br />
                      at {String(home.nextBoundaryUtc).padStart(2, "0")}:00 UTC, in {formatDuration(home.msToHandoff)}
                    </>
                  ) : (
                    "Reading the UTC clock"
                  )}
                </span>
              </div>
              <DayRule home={home} />
            </div>

            <ol className="data text-[12.5px] leading-tight" aria-label="Stamp log">
              <StampLine on={phase >= 1} label="RX" value={order.rx.slice(6)} note="NIC hardware time" />
              <StampLine on={phase >= 2} label="CUT" value="+ ~150 ns" note="cut vector logged" />
              <StampLine on={phase >= 3} label="FILL" value="+ ≤ 965 ns" note="NIC 560 + engine 405" />
              <StampLine on={phase >= 4} label="FINAL" value="+ ~3 ms" note="3 of 4 signed · BASE" />
            </ol>
            <div className="flex items-center justify-between gap-3 border-t-2 border-ink px-5 py-3">
              <span className="text-[12.5px] leading-tight text-ink-soft">Simulated on spec budgets, slowed so you can read it.</span>
              <button
                type="button"
                onClick={() => {
                  run(nextOrder(order));
                  track("stamp_order");
                  // On narrow screens the stamps sit above the button; bring them into view to watch them land.
                  const box = pad.current?.getBoundingClientRect();
                  if (box && box.height > 0 && (box.top < 64 || box.bottom > window.innerHeight)) {
                    pad.current?.scrollIntoView({ block: "center", behavior: prefersReducedMotion() ? "auto" : "smooth" });
                  }
                }}
                className="flex-none border-2 border-ink bg-canary px-3 py-2 text-[14px] font-extrabold [font-stretch:112%] hover:bg-ink hover:text-canary"
              >
                Stamp an order
              </button>
            </div>
          </aside>
        </div>

        <div className="border-t-2 border-ink">
          <div className="flex flex-wrap items-baseline justify-between gap-2 border-b-2 border-ink px-4 py-2 sm:px-6">
            <span className="caption">One <span className="data normal-case">New</span> message · 16 bytes</span>
            <Link href="/docs/01-conventions#62-messages-16-bytes-each" className="caption text-ink-soft">
              Layout: 01 §6.2
            </Link>
          </div>
          <dl className="grid grid-cols-2 gap-[2px] bg-ink sm:grid-cols-3 lg:grid-cols-[0.8fr_1.3fr_0.6fr_1.2fr_1.2fr_1.2fr]">
            <Field bytes="0" name="Type" value="New" sub="0x01" />
            <Field bytes="1" name="Flags" value={<span className={sideClass}>{order.side} · IOC</span>} sub={hex(flagsByte(order.side), 2)} />
            <Field bytes="2–3" name="Reserved" value="0" sub="0x0000" />
            <Field bytes="4–7" name="Tick u32" value={order.tick.toLocaleString("en-US")} sub={hex(order.tick, 8)} />
            <Field bytes="8–11" name="Qty u32" value={order.qty.toLocaleString("en-US")} sub={hex(order.qty, 8)} />
            <Field bytes="12–15" name="Client tag u32" value={hex(order.tag, 4)} sub={hex(order.tag, 8)} />
          </dl>
        </div>

        <nav aria-label="Where to go next" className="grid gap-[2px] border-t-2 border-ink bg-ink sm:grid-cols-3 lg:grid-cols-[1.35fr_1fr_1fr_1fr]">
          <div className="hidden lg:grid">
            <Link href="/docs/design" className="routebox primary" onClick={() => track("route_click", { to: "design", from: "hero" })}>
              <span className="box"><Arrow /></span>
              <span>Read the design<small>The answer in one document</small></span>
            </Link>
          </div>
          <Link href="/docs/00-index" className="routebox bg-canary" onClick={() => track("route_click", { to: "spec", from: "hero" })}>
            <span className="box"><Arrow /></span>
            <span>Read the spec<small>Chapters 00–14</small></span>
          </Link>
          <a href={REPO_URL} className="routebox bg-canary" onClick={() => track("route_click", { to: "github", from: "hero" })}>
            <span className="box"><Arrow /></span>
            <span>GitHub<small>bajpainaman/VYRN</small></span>
          </a>
          <a href={LICENSE_REQUEST_URL} className="routebox bg-canary" onClick={() => track("route_click", { to: "license_request", from: "hero" })}>
            <span className="box"><Arrow /></span>
            <span>Request a license<small>Firms need written permission</small></span>
          </a>
        </nav>
      </article>
      </div>
    </section>
  );
}

/** The stamp face (Doto) draws "~" like a caret; set the approximation mark in the data face so it reads. */
function Approx({ children }: { children: string }) {
  const [mark, ...rest] = children.split("~");
  return (
    <>
      {mark}
      {rest.map((part, i) => (
        <span key={i}>
          <span className="font-[family-name:var(--font-data)] font-semibold">~</span>
          {part}
        </span>
      ))}
    </>
  );
}

function Stamp({ on, run, rot, className, label, size, children }: { on: boolean; run: number; rot: string; className: string; label: string; size: string; children: ReactNode }) {
  return (
    <div
      key={on ? `on-${run}` : "off"}
      data-stamp
      className={`${on ? "strike" : "invisible"} ${className}`}
      style={{ ["--rot" as string]: rot }}
    >
      <span className={`stamp ${size}`}>
        <span className="stamp-label">{label}</span>
        {children}
      </span>
    </div>
  );
}

function Field({ bytes, name, value, sub }: { bytes: string; name: string; value: ReactNode; sub: string }) {
  return (
    <div className="bg-canary px-4 py-2.5 sm:px-5">
      <dt className="caption flex justify-between gap-2">
        <span>{name}</span>
        <span className="data whitespace-nowrap font-normal normal-case tracking-normal text-ink-soft">b{bytes}</span>
      </dt>
      <dd className="data mt-1.5 text-[clamp(17px,1.6vw,24px)] font-semibold leading-tight">{value}</dd>
      <dd className="data mt-0.5 text-[12px] text-ink-soft">{sub}</dd>
    </div>
  );
}

function StampLine({ on, label, value, note }: { on: boolean; label: string; value: string; note: string }) {
  return (
    <li className="grid grid-cols-[52px_1fr] items-baseline gap-x-3 border-b border-ink/25 px-5 py-2 last:border-b-0">
      <span className={`font-semibold transition-colors duration-150 ${on ? "text-stamp" : "text-ink-soft"}`}>{label}</span>
      <span data-stamp className={on ? "" : "text-ink-soft"}>
        <span className="font-semibold">{on ? value : "—"}</span>
        <span className="block pt-0.5 font-[family-name:var(--font-display)] text-[12px] text-ink-soft">{note}</span>
      </span>
    </li>
  );
}

/** The UTC day as three 8-hour homes, with a mark at the current time. */
function DayRule({ home }: { home: HomeState | null }) {
  return (
    <div className="mt-3" aria-hidden>
      <div className="relative grid h-7 grid-cols-3 border-2 border-ink">
        {HOMES.map((h, i) => (
          <span
            key={h}
            className={`caption grid place-items-center ${i < 2 ? "border-r-2 border-ink" : ""} ${home?.home === h ? "bg-ink text-canary" : ""}`}
          >
            {h}
          </span>
        ))}
        {home && (
          <span className="absolute -bottom-[11px] h-[8px] w-[3px] bg-stamp" style={{ left: `calc(${(home.dayFraction * 100).toFixed(2)}% - 1.5px)` }} />
        )}
      </div>
      <div className="data mt-3 grid grid-cols-3 text-[11px] text-ink-soft">
        <span>00:00</span>
        <span>08:00</span>
        <span>16:00 UTC</span>
      </div>
    </div>
  );
}
