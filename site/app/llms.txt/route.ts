import { llmsTxt } from "@/lib/agent";

export async function GET() {
  return new Response(await llmsTxt(), { headers: { "Content-Type": "text/markdown; charset=utf-8" } });
}
