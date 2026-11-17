import Link from "next/link";
import { Arrow } from "@/components/Arrow";

export default function NotFound() {
  return (
    <main id="main" className="mx-auto w-full max-w-[1440px] flex-1 px-4 py-10 sm:px-8">
      <div className="border-2 border-ink bg-canary">
        <div className="relative px-5 pb-10 pt-8 sm:px-8">
          <h1 className="display max-w-[14ch] text-[clamp(2.6rem,6vw,5rem)]">No ticket at this address.</h1>
          <p className="mt-4 max-w-[52ch] text-[18px]">
            The page does not exist. The design and the fifteen spec chapters are below.
          </p>
          <span className="stamp mt-6 rotate-[-4deg] text-[22px]">
            <span className="stamp-label">Reject · unknown route</span>
            404
          </span>
        </div>
        <nav aria-label="Where to go next" className="grid gap-[2px] border-t-2 border-ink bg-ink sm:grid-cols-3">
          <Link href="/" className="routebox primary">
            <span className="box"><Arrow /></span>
            <span>Back to the ticket<small>The landing page</small></span>
          </Link>
          <Link href="/docs/design" className="routebox bg-canary">
            <span className="box"><Arrow /></span>
            <span>Read the design<small>DESIGN.md</small></span>
          </Link>
          <Link href="/docs/00-index" className="routebox bg-canary">
            <span className="box"><Arrow /></span>
            <span>Read the spec<small>Chapters 00–14</small></span>
          </Link>
        </nav>
      </div>
    </main>
  );
}
