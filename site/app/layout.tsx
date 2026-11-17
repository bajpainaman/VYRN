import type { Metadata } from "next";
import { Archivo, Doto, Martian_Mono } from "next/font/google";
import { Analytics } from "@vercel/analytics/next";
import { SpeedInsights } from "@vercel/speed-insights/next";
import { SiteHeader } from "@/components/SiteHeader";
import "./globals.css";

const archivo = Archivo({ variable: "--font-archivo", subsets: ["latin"], axes: ["wdth"] });
const martian = Martian_Mono({ variable: "--font-martian", subsets: ["latin"], axes: ["wdth"] });
const doto = Doto({ variable: "--font-doto", subsets: ["latin"], weight: ["700", "800"] });

// The canonical origin: set NEXT_PUBLIC_SITE_URL for a custom domain; on Vercel the production URL is known.
const SITE_URL =
  process.env.NEXT_PUBLIC_SITE_URL ??
  (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : "http://localhost:3000");

const THEME_SCRIPT =
  "(function(){var d=document.documentElement;d.classList.add('js');try{var t=localStorage.getItem('vyrn-theme');if(t==='light'||t==='dark')d.dataset.theme=t}catch(e){}})()";

const DESCRIPTION =
  "VYRN is an exchange design: a fill at most 1 µs after the first bit arrives, 1B messages a second on one book, BFT finality within 10 ms, and a book that follows the sun. Every figure is a design budget.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: "VYRN: a 1 µs exchange with no FPGA", template: "%s · VYRN" },
  description: DESCRIPTION,
  openGraph: {
    type: "website",
    siteName: "VYRN",
    title: "VYRN: filled within 1 µs of the first bit",
    description: DESCRIPTION,
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "A VYRN order ticket stamped: filled within 965 ns, final in about 3 ms." }],
  },
  twitter: { card: "summary_large_image", title: "VYRN: filled within 1 µs of the first bit", description: DESCRIPTION, images: ["/og.png"] },
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" suppressHydrationWarning className={`${archivo.variable} ${martian.variable} ${doto.variable} antialiased`}>
      <head>
        {/* Runs before first paint: marks JavaScript as present and applies a saved theme (ThemeToggle), so a
            reader who chose Dark never sees a light frame. Without a saved choice the CSS follows the OS. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="min-h-dvh flex flex-col">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-3 focus:z-50 focus:bg-slab focus:px-3 focus:py-2 focus:text-on-slab"
        >
          Skip to content
        </a>
        <SiteHeader />
        {children}
        {/* Vercel Web Analytics and Speed Insights: cookieless, and inert outside a Vercel deployment. */}
        <Analytics />
        <SpeedInsights />
      </body>
    </html>
  );
}
