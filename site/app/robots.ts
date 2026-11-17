import type { MetadataRoute } from "next";
import { SITE_ORIGIN } from "@/lib/agent";

/** Open to every crawler and agent: the spec is meant to be read. */
export default function robots(): MetadataRoute.Robots {
  return { rules: [{ userAgent: "*", allow: "/" }], sitemap: `${SITE_ORIGIN}/sitemap.xml`, host: SITE_ORIGIN };
}
