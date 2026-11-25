"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { FormEvent, useState } from "react";
import { api, errorCode, safeNext, setCsrfToken } from "@/lib/api";
import { messageFor } from "@/lib/messages";

export default function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const [error, setError] = useState<string | null>(messageFor(params.get("error")));
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const res = await api.post("/auth/login", { email: form.get("email"), password: form.get("password") });
      setCsrfToken(res.data.csrfToken); // rotated at login
      router.replace(next);
    } catch (err) {
      setError(messageFor(errorCode(err)));
    } finally {
      setBusy(false);
    }
  }

  const oauthHref = (provider: string) => `/api/auth/oauth/${provider}/start?next=${encodeURIComponent(next)}`;

  return (
    <div className="card">
      <h1>Sign in</h1>
      {error && <p className="error" role="alert">{error}</p>}
      <form onSubmit={onSubmit}>
        <label>
          E-mail
          <input name="email" type="email" autoComplete="username" required maxLength={320} />
        </label>
        <label>
          Password
          <input name="password" type="password" autoComplete="current-password" required maxLength={128} />
        </label>
        <button disabled={busy}>{busy ? "Signing in..." : "Sign in"}</button>
      </form>
      <p className="muted">or</p>
      <div className="row">
        {/* Plain navigations: the backend redirects to the provider with state + PKCE. */}
        <a className="button secondary" href={oauthHref("google")}>Continue with Google</a>
        <a className="button secondary" href={oauthHref("github")}>Continue with GitHub</a>
      </div>
    </div>
  );
}
