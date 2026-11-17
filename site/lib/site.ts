export const REPO_URL = "https://github.com/bajpainaman/VYRN";
export const LICENSE_URL = `${REPO_URL}/blob/main/LICENSE`;
/** A license request opens the repo's issue form, which asks the README's questions and applies the license label. */
export const LICENSE_REQUEST_URL = `${REPO_URL}/issues/new?template=license-request.yml`;

/** Public contact address. Unset hides every contact route rather than showing a dead one. */
export const CONTACT_EMAIL: string | undefined = process.env.NEXT_PUBLIC_CONTACT_EMAIL?.trim() || undefined;

export const SPEC_DRAFT = "Draft 0.2";
export const SPEC_DATE = "2026-11-13";
