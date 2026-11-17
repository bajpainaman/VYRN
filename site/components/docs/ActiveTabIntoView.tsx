"use client";

import { useEffect } from "react";

/** On the narrow horizontal binder, brings the current chapter's tab into view. */
export function ActiveTabIntoView() {
  useEffect(() => {
    const tab = document.querySelector<HTMLElement>('[data-binder] [aria-current="page"]');
    const strip = tab?.closest("ol");
    if (!tab || !strip || strip.scrollWidth <= strip.clientWidth) return;
    strip.scrollLeft = tab.offsetLeft - (strip.clientWidth - tab.offsetWidth) / 2;
  }, []);
  return null;
}
