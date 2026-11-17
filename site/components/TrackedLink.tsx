"use client";

import Link from "next/link";
import { track } from "@vercel/analytics";
import type { ComponentProps } from "react";

type Props = ComponentProps<"a"> & { href: string; event: string; eventProps?: Record<string, string | number | boolean> };

/** A link that records a named Vercel Analytics event on click. Internal hrefs use Next's Link. */
export function TrackedLink({ href, event, eventProps, onClick, ...rest }: Props) {
  const handle: Props["onClick"] = (e) => {
    track(event, eventProps);
    onClick?.(e);
  };
  return href.startsWith("/") ? <Link href={href} onClick={handle} {...rest} /> : <a href={href} onClick={handle} {...rest} />;
}
