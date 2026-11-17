import type { ReactNode } from "react";
import { SiteFooter } from "./SiteFooter";

/** A plain reading page on the white ply, for About, Contact, Developers and Privacy. */
export function PlainPage({ title, children }: { title: string; children: ReactNode }) {
  return (
    <>
      <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-10 sm:px-8">
        <article className="ticket relative border-2 border-ink bg-ply py-8 pl-7 pr-5 sm:pl-9 sm:pr-8">
          <h1 className="display max-w-[18ch] text-[clamp(2.4rem,5vw,4rem)]">{title}</h1>
          <div className="prose-spec mt-6">{children}</div>
        </article>
      </main>
      <SiteFooter />
    </>
  );
}
