// Fixed messages for fixed codes. Nothing from the URL is ever rendered verbatim.
export const ERROR_MESSAGES: Record<string, string> = {
  invalid_credentials: "Wrong e-mail or password.",
  rate_limited: "Too many attempts. Wait a few minutes and try again.",
  validation_error: "Please check the form: valid e-mail, password of 12 to 128 characters.",
  email_taken: "An account with this e-mail already exists. Sign in instead.",
  csrf_failed: "Your form expired. Please try again.",
  bad_origin: "Request blocked.",
  oauth_denied: "Sign-in was cancelled at the provider.",
  oauth_state_invalid: "The sign-in link expired or was not started in this browser. Please try again.",
  token_exchange_failed: "The provider rejected the sign-in. Please try again.",
  invalid_id_token: "The provider's identity token could not be verified.",
  profile_fetch_failed: "Could not read your profile from the provider.",
  provider_unreachable: "The provider could not be reached. Please try again.",
  email_unverified: "Your e-mail at the provider is not verified, so we cannot use it.",
  account_exists:
    "An account with this e-mail already exists. Sign in with your password, then link the provider from your dashboard.",
  identity_linked_elsewhere: "That provider account is already linked to a different user.",
  provider_already_linked: "You already linked an account from this provider.",
  account_disabled: "This account is disabled.",
  session_expired: "Your session ended. Please sign in again.",
};

export function messageFor(code: string | null | undefined): string | null {
  if (!code) return null;
  return ERROR_MESSAGES[code] ?? "Something went wrong. Please try again.";
}
