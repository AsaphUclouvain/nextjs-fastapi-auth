import Link from "next/link";

export default function Home() {
  return (
    <div className="card">
      <h1>authapp</h1>
      <p>Next.js frontend, FastAPI backend, Redis for refresh tokens, OAuth state and rate limits.</p>
      <div className="row">
        <Link className="button" href="/login">Sign in</Link>
        <Link className="button secondary" href="/register">Create account</Link>
        <Link className="button secondary" href="/guest">Continue as guest</Link>
      </div>
    </div>
  );
}
