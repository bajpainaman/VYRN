import type { MetadataRoute } from "next";
import { getChapterSummaries, SITE_ORIGIN } from "@/lib/agent";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const chapters = await getChapterSummaries();
  return [
    { url: SITE_ORIGIN, changeFrequency: "weekly", priority: 1 },
    ...chapters.map((c) => ({ url: c.url, changeFrequency: "weekly" as const, priority: c.slug === "design" ? 0.9 : 0.7 })),
    { url: `${SITE_ORIGIN}/developers`, changeFrequency: "monthly", priority: 0.6 },
    { url: `${SITE_ORIGIN}/about`, changeFrequency: "yearly", priority: 0.4 },
    { url: `${SITE_ORIGIN}/contact`, changeFrequency: "yearly", priority: 0.4 },
    { url: `${SITE_ORIGIN}/privacy`, changeFrequency: "yearly", priority: 0.2 },
  ];
}
