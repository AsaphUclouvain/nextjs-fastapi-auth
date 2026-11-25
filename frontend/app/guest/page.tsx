import Link from "next/link";

type GuestData = { title: string; cards: { label: string; value: string | number }[]; cta: string };

// Server component: public data only, fetched server-side without forwarding any cookies.
async function load(): Promise<GuestData | null> {
  const backend = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";
  try {
    const res = await fetch(`${backend}/api/dashboard/guest`, { cache: "no-store" });
    return res.ok ? ((await res.json()) as GuestData) : null;
  } catch {
    return null;
  }
}

export default async function GuestDashboard() {
  const data = await load();
  if (!data) return <p className="error">The API is not reachable.</p>;
  return (
    <>
      <h1>{data.title}</h1>
      <div className="grid">
        {data.cards.map((c) => (
          <div className="card" key={c.label}>
            <div className="muted">{c.label}</div>
            <div className="big">{c.value}</div>
          </div>
        ))}
      </div>
      <p>
        {data.cta} <Link href="/login?next=/dashboard">Sign in</Link>
      </p>
    </>
  );
}
