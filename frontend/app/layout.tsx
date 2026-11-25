import type { Metadata } from "next";
import Link from "next/link";
import { headers } from "next/headers";
import "./globals.css";

export const metadata: Metadata = { title: "authapp", description: "Minimal Next.js + FastAPI auth demo" };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Reading request headers makes every page dynamic, which the nonce-based CSP requires.
  await headers();
  return (
    <html lang="en">
      <body>
        <nav>
          <Link href="/">Home</Link>
          <Link href="/guest">Guest dashboard</Link>
          <Link href="/dashboard">My dashboard</Link>
          <Link href="/login">Sign in</Link>
          <Link href="/register">Register</Link>
        </nav>
        <main>{children}</main>
      </body>
    </html>
  );
}
