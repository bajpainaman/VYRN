/** RFC 9116 security.txt, served at /.well-known/security.txt through a rewrite in next.config. */
export async function GET() {
  const expires = "2027-11-17T00:00:00.000Z";
  const body = [
    "Contact: https://github.com/bajpainaman/VYRN/security/advisories/new",
    `Expires: ${expires}`,
    "Preferred-Languages: en",
    "Canonical: https://www.vryn.trade/.well-known/security.txt",
    "Policy: https://github.com/bajpainaman/VYRN/security/policy",
    "",
  ].join("\n");
  return new Response(body, { headers: { "Content-Type": "text/plain; charset=utf-8" } });
}
