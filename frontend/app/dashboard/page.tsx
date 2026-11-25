"use client";

// Client-rendered so the axios interceptor can refresh an expired access token transparently.
// Hiding the admin panel here is UX only: every endpoint checks permissions on the server.
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api, errorCode, logout, Me, onSessionEnded } from "@/lib/api";

type Dashboard = { title: string; tasks: { id: number; title: string; done: boolean }[] };
type AdminUsers = { users: { id: string; email: string; role: string; active: boolean }[] };

const PROVIDER_URL_PREFIX: Record<string, string> = {
  google: "https://accounts.google.com/",
  github: "https://github.com/login/oauth/",
};

export default function DashboardPage() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [data, setData] = useState<Dashboard | null>(null);
  const [admin, setAdmin] = useState<AdminUsers | null>(null);
  const [note, setNote] = useState<string | null>(null);

  useEffect(() => onSessionEnded(() => router.replace("/login?next=/dashboard")), [router]);

  const load = useCallback(async () => {
    try {
      // Fired in parallel on purpose: if the access token expired, both get 401 and share one refresh.
      const [meRes, dashRes] = await Promise.all([api.get<Me>("/me"), api.get<Dashboard>("/dashboard")]);
      setMe(meRes.data);
      setData(dashRes.data);
      if (meRes.data.permissions.includes("users:read")) {
        setAdmin((await api.get<AdminUsers>("/admin/users")).data);
      }
    } catch (err) {
      if (errorCode(err) !== "invalid_refresh") setNote(`Could not load: ${errorCode(err)}`);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function link(provider: string) {
    const res = await api.post<{ authorizationUrl: string }>(`/auth/oauth/${provider}/link`);
    const url = res.data.authorizationUrl;
    if (url.startsWith(PROVIDER_URL_PREFIX[provider])) window.location.assign(url);
  }

  async function burst() {
    const results = await Promise.allSettled(Array.from({ length: 5 }, () => api.get("/me")));
    setNote(`5 parallel requests: ${results.filter((r) => r.status === "fulfilled").length} succeeded`);
  }

  if (!me || !data) return <p className="muted">{note ?? "Loading..."}</p>;

  return (
    <>
      <h1>{data.title}</h1>
      <div className="card">
        <p>
          {me.email} · role <b>{me.role}</b>
        </p>
        <p className="muted">Permissions: {me.permissions.join(", ")}</p>
        <ul>
          {data.tasks.map((t) => (
            <li key={t.id}>
              {t.done ? "✓ " : "○ "}
              {t.title}
            </li>
          ))}
        </ul>
      </div>

      <div className="card">
        <h2>Linked sign-in methods</h2>
        <p className="muted">
          Password: {me.hasPassword ? "yes" : "no"} · Providers: {me.linkedProviders.join(", ") || "none"}
        </p>
        <div className="row">
          {["google", "github"]
            .filter((p) => !me.linkedProviders.includes(p))
            .map((p) => (
              <button key={p} className="secondary" onClick={() => link(p)}>
                Link {p === "google" ? "Google" : "GitHub"}
              </button>
            ))}
        </div>
      </div>

      {admin && (
        <div className="card">
          <h2>Admin: users</h2>
          <ul>
            {admin.users.map((u) => (
              <li key={u.id}>
                {u.email} ({u.role}){u.active ? "" : " disabled"}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="row">
        <button className="secondary" onClick={burst}>Fire 5 parallel requests</button>
        <button onClick={() => logout(false)}>Sign out</button>
        <button className="secondary" onClick={() => logout(true)}>Sign out everywhere</button>
      </div>
      {note && <p className="muted">{note}</p>}
    </>
  );
}
