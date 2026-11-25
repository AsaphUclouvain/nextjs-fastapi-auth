"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { api, errorCode, setCsrfToken } from "@/lib/api";
import { messageFor } from "@/lib/messages";

export default function RegisterPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    if (form.get("password") !== form.get("confirm")) {
      setError("The two passwords do not match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await api.post("/auth/register", {
        email: form.get("email"),
        password: form.get("password"),
        display_name: form.get("display_name"),
      });
      setCsrfToken(res.data.csrfToken);
      router.replace("/dashboard");
    } catch (err) {
      setError(messageFor(errorCode(err)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h1>Create account</h1>
      {error && <p className="error" role="alert">{error}</p>}
      <form onSubmit={onSubmit}>
        <label>
          Display name
          <input name="display_name" required maxLength={50} autoComplete="nickname" />
        </label>
        <label>
          E-mail
          <input name="email" type="email" required maxLength={320} autoComplete="username" />
        </label>
        <label>
          Password (12 to 128 characters)
          <input name="password" type="password" required minLength={12} maxLength={128} autoComplete="new-password" />
        </label>
        <label>
          Repeat password
          <input name="confirm" type="password" required minLength={12} maxLength={128} autoComplete="new-password" />
        </label>
        <button disabled={busy}>{busy ? "Creating..." : "Create account"}</button>
      </form>
    </div>
  );
}
