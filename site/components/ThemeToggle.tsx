"use client";

import { useSyncExternalStore } from "react";

type Theme = "light" | "dark" | "system";

/** Shared with the layout's inline script, which applies the saved choice before first paint. */
const KEY = "vyrn-theme";
const CHANGE = "vyrn-theme-change";

const OPTIONS: { value: Theme; label: string; note: string }[] = [
  { value: "light", label: "Light", note: "Canary ply" },
  { value: "dark", label: "Dark", note: "Carbon sheet" },
  { value: "system", label: "System", note: "Follows your device" },
];

/** The saved choice, or System when there is none or storage is blocked. */
function saved(): Theme {
  try {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

/** The applied theme is the root's data-theme, so the menu matches the page even when storage is blocked. */
function read(): Theme {
  const theme = document.documentElement.dataset.theme;
  return theme === "light" || theme === "dark" ? theme : "system";
}

/** "system" leaves data-theme unset, so the root's `color-scheme: light dark` follows the OS. */
function apply(theme: Theme) {
  const root = document.documentElement;
  if (theme === "system") delete root.dataset.theme;
  else root.dataset.theme = theme;
}

function choose(theme: Theme) {
  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    // Storage blocked: the choice still holds for this page.
  }
  apply(theme);
  window.dispatchEvent(new Event(CHANGE));
}

function subscribe(onChange: () => void) {
  // A choice made in another tab arrives as a storage event; apply it here too.
  const onStorage = (event: StorageEvent) => {
    if (event.key !== KEY && event.key !== null) return;
    apply(saved());
    onChange();
  };
  window.addEventListener("storage", onStorage);
  window.addEventListener(CHANGE, onChange);
  return () => {
    window.removeEventListener("storage", onStorage);
    window.removeEventListener(CHANGE, onChange);
  };
}

function Icon({ theme }: { theme: Theme }) {
  const common = { width: 20, height: 20, viewBox: "0 0 20 20", fill: "none", stroke: "currentColor", strokeWidth: 2, "aria-hidden": true } as const;
  if (theme === "light")
    return (
      <svg {...common} strokeLinecap="square">
        <circle cx="10" cy="10" r="3.5" />
        <path d="M10 1.5v2.5M10 16v2.5M1.5 10h2.5M16 10h2.5M4 4l1.7 1.7M14.3 14.3 16 16M4 16l1.7-1.7M14.3 5.7 16 4" />
      </svg>
    );
  if (theme === "dark")
    return (
      <svg {...common}>
        <path d="M16.5 12.6A7 7 0 0 1 7.4 3.5a7 7 0 1 0 9.1 9.1Z" />
      </svg>
    );
  return (
    <svg {...common}>
      <circle cx="10" cy="10" r="7" />
      <path d="M10 3a7 7 0 0 1 0 14Z" fill="currentColor" stroke="none" />
    </svg>
  );
}

/**
 * The header's theme cell. Its icon is chosen by CSS from the root's data-theme, so it is right before
 * hydration; the menu's radios read the saved choice once the page is interactive.
 */
export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, read, () => null);
  return (
    <>
      <button
        type="button"
        popoverTarget="theme-menu"
        aria-label="Colour theme"
        className="theme-button flex items-center border-l-2 border-ink px-2 hover:bg-canary-shade sm:px-4"
      >
        <span className="theme-icon" data-for="light"><Icon theme="light" /></span>
        <span className="theme-icon" data-for="dark"><Icon theme="dark" /></span>
        <span className="theme-icon" data-for="system"><Icon theme="system" /></span>
      </button>
      <div id="theme-menu" popover="auto" className="theme-menu border-2 border-ink bg-ply text-ink">
        <fieldset>
          <legend className="caption block w-full border-b-2 border-ink px-4 py-2.5 text-ink-mute">Theme</legend>
          {OPTIONS.map((option) => (
            <label
              key={option.value}
              className="flex cursor-pointer items-center gap-3 border-b border-ink/25 px-4 py-2.5 last:border-b-0 hover:bg-canary-shade has-[:focus-visible]:outline-2 has-[:focus-visible]:-outline-offset-4 has-[:focus-visible]:outline-stamp"
            >
              <input
                type="radio"
                name="theme"
                value={option.value}
                checked={theme === option.value}
                onChange={() => choose(option.value)}
                className="peer sr-only"
              />
              <span className="grid size-[18px] flex-none place-items-center border-2 border-ink text-on-slab peer-checked:bg-slab" aria-hidden>
                {theme === option.value && (
                  <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="square">
                    <path d="M1.5 5.2 4 7.6 8.6 2.4" />
                  </svg>
                )}
              </span>
              <Icon theme={option.value} />
              <span className="flex flex-col">
                <span className="text-[15px] font-bold leading-tight [font-stretch:112%]">{option.label}</span>
                <span className="text-[12.5px] leading-tight text-ink-mute">{option.note}</span>
              </span>
            </label>
          ))}
        </fieldset>
      </div>
    </>
  );
}
