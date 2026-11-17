import { ImageResponse } from "next/og";
import { getChapterDetail, getChapterSummaries } from "@/lib/agent";

export const size = { width: 1200, height: 630 };
export const contentType = "image/png";
export const alt = "A VYRN spec chapter as an order ticket";

export async function generateStaticParams() {
  return (await getChapterSummaries()).map((c) => ({ slug: c.slug }));
}

/** Each chapter's share card: an order ticket with the chapter number stamped in violet. */
export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const chapter = await getChapterDetail(slug);
  if (!chapter) throw new Error(`opengraph-image: unknown chapter "${slug}"`);
  return new ImageResponse(
    (
      <div style={{ width: "100%", height: "100%", display: "flex", background: "#F4B7C2", padding: "24px 44px 44px 28px" }}>
        <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "#F2D447", border: "4px solid #191B26", color: "#191B26" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "18px 36px", borderBottom: "4px solid #191B26", fontSize: 28, fontWeight: 800 }}>
            <span>VYRN · Spec</span>
            <span style={{ fontSize: 22 }}>{chapter.lines.toLocaleString("en-US")} lines · draft 0.2</span>
          </div>
          <div style={{ flex: 1, display: "flex", flexDirection: "column", justifyContent: "center", padding: "0 36px" }}>
            <div style={{ display: "flex" }}>
              <span style={{ color: "#5A2D91", border: "5px solid #5A2D91", padding: "4px 18px", fontSize: 44, fontWeight: 800, transform: "rotate(-3deg)" }}>
                {chapter.number}
              </span>
            </div>
            <div style={{ marginTop: 26, fontSize: chapter.title.length > 42 ? 64 : 78, fontWeight: 800, lineHeight: 1.02, letterSpacing: -1 }}>{chapter.title}</div>
          </div>
          <div style={{ display: "flex", borderTop: "4px solid #191B26", padding: "16px 36px", fontSize: 24, fontWeight: 700 }}>
            www.vryn.trade/docs/{chapter.slug}
          </div>
        </div>
      </div>
    ),
    size,
  );
}
