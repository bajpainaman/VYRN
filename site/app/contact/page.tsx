import type { Metadata } from "next";
import { PlainPage } from "@/components/PlainPage";
import { CONTACT_EMAIL, LICENSE_REQUEST_URL, REPO_URL } from "@/lib/site";

export const metadata: Metadata = {
  title: "Contact",
  description: "How to reach the VYRN project: license requests, questions about the spec, and security reports.",
  alternates: { canonical: "/contact" },
};

export default function ContactPage() {
  return (
    <PlainPage title="Contact">
      <p>VYRN is run in the open on GitHub. Pick the route that matches what you need.</p>
      <h2>License requests</h2>
      <p>
        Commercial or production use, and any use by a financial institution or a government body, needs written permission
        first. <a href={LICENSE_REQUEST_URL}>Open a license request</a>: the form asks who you represent and how you plan to use
        VYRN. Requests are public GitHub issues, so leave out anything confidential. Opening one does not grant permission.
      </p>
      <h2>Questions and corrections to the spec</h2>
      <p>
        <a href={`${REPO_URL}/issues`}>Open an issue</a> on the repository and name the chapter and section (for example
        &ldquo;05 §6.8&rdquo;). Every section on this site has a copyable anchor link you can paste into the issue.
      </p>
      <h2>Security reports</h2>
      <p>
        Report vulnerabilities in this site or the spec privately through{" "}
        <a href={`${REPO_URL}/security/advisories/new`}>GitHub security advisories</a>, not in a public issue. The same address
        is published in <a href="/.well-known/security.txt">security.txt</a>.
      </p>
      {CONTACT_EMAIL && (
        <>
          <h2>Email</h2>
          <p>
            For a private conversation, write to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
          </p>
        </>
      )}
    </PlainPage>
  );
}
