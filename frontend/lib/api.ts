/**
 * Axios client with two interceptors.
 *
 * Request:  adds X-CSRF-Token to every unsafe method (token fetched once from /api/auth/csrf).
 * Response: on 401 from a data endpoint -> refresh once -> replay the original request once.
 *
 * Concurrency, in three layers:
 *  1. Single-flight inside a tab: all requests that hit 401 at the same time await ONE refresh promise.
 *  2. Across tabs: the Web Locks API serialises refreshes; a tab that gets the lock after another
 *     tab already refreshed (timestamp in localStorage newer than its failed request) just replays.
 *  3. Server: a rotated refresh token stays usable for ~10 s (access token only, no new refresh
 *     token), so a race that slips through layers 1-2 does not trip reuse detection.
 *
 * Tokens never touch JavaScript: they live in HttpOnly cookies. JS only holds the CSRF token.
 */
import axios, { AxiosError, InternalAxiosRequestConfig } from "axios";

type Config = InternalAxiosRequestConfig & { _retried?: boolean; _csrfRetried?: boolean; _sentAt?: number };

const UNSAFE = new Set(["post", "put", "patch", "delete"]);
// 401s from these mean "bad credentials / no session", not "access token expired".
const NO_REFRESH = ["/auth/login", "/auth/register", "/auth/refresh", "/auth/logout", "/auth/csrf"];
const LAST_REFRESH_KEY = "auth:lastRefreshAt";
const channel = typeof window !== "undefined" && "BroadcastChannel" in window ? new BroadcastChannel("auth") : null;

export const api = axios.create({
  baseURL: "/api",
  timeout: 15_000,
  headers: { "Content-Type": "application/json", Accept: "application/json" },
});

// ---- CSRF -----------------------------------------------------------------------------------
let csrfToken: string | null = null;
let csrfPromise: Promise<string> | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

async function getCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  csrfPromise ??= axios
    .get<{ csrfToken: string }>("/api/auth/csrf")
    .then((r) => (csrfToken = r.data.csrfToken))
    .finally(() => (csrfPromise = null));
  return csrfPromise;
}

// ---- refresh (single-flight + cross-tab lock) -------------------------------------------------
let refreshPromise: Promise<void> | null = null;

async function postRefresh(): Promise<void> {
  try {
    await axios.post("/api/auth/refresh", null, { headers: { "X-CSRF-Token": await getCsrfToken() } });
  } catch (e) {
    const err = e as AxiosError<{ detail?: string }>;
    if (err.response?.status === 403 && err.response.data?.detail === "csrf_failed") {
      csrfToken = null; // CSRF cookie was rotated (e.g. login in another tab): fetch and try once more
      await axios.post("/api/auth/refresh", null, { headers: { "X-CSRF-Token": await getCsrfToken() } });
      return;
    }
    throw e;
  }
}

async function refreshWithLock(failedAt: number): Promise<void> {
  const run = async () => {
    const last = Number(localStorage.getItem(LAST_REFRESH_KEY) ?? 0);
    if (last > failedAt) return; // another tab refreshed after our request was sent; cookies are shared
    await postRefresh();
    localStorage.setItem(LAST_REFRESH_KEY, String(Date.now()));
  };
  if (typeof navigator !== "undefined" && navigator.locks) {
    await navigator.locks.request("auth-refresh", run);
  } else {
    await run();
  }
}

export function refreshSession(failedAt: number = Date.now()): Promise<void> {
  refreshPromise ??= refreshWithLock(failedAt).finally(() => (refreshPromise = null));
  return refreshPromise;
}

// ---- session-ended notifications -------------------------------------------------------------
type Listener = () => void;
const listeners = new Set<Listener>();

export function onSessionEnded(listener: Listener): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function sessionEnded(broadcast = true) {
  csrfToken = null;
  if (broadcast) channel?.postMessage("logout");
  listeners.forEach((l) => l());
}
channel?.addEventListener("message", (e) => e.data === "logout" && sessionEnded(false));

// ---- interceptors ----------------------------------------------------------------------------
api.interceptors.request.use(async (config: Config) => {
  config._sentAt = Date.now();
  if (UNSAFE.has((config.method ?? "get").toLowerCase())) {
    config.headers.set("X-CSRF-Token", await getCsrfToken());
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<{ detail?: string }>) => {
    const config = error.config as Config | undefined;
    const status = error.response?.status;
    if (!config) throw error;

    if (status === 403 && error.response?.data?.detail === "csrf_failed" && !config._csrfRetried) {
      config._csrfRetried = true;
      csrfToken = null;
      return api.request(config); // the request interceptor attaches a fresh token
    }

    const url = config.url ?? "";
    if (status === 401 && !config._retried && !NO_REFRESH.some((p) => url.startsWith(p))) {
      config._retried = true; // replay at most once: no refresh loops
      try {
        await refreshSession(config._sentAt);
      } catch {
        sessionEnded();
        throw error;
      }
      return api.request(config);
    }
    throw error;
  },
);

// ---- auth actions ----------------------------------------------------------------------------
export type Me = {
  id: string;
  email: string;
  displayName: string;
  role: string;
  permissions: string[];
  linkedProviders: string[];
  hasPassword: boolean;
};

export async function logout(allDevices = false) {
  try {
    await api.post(allDevices ? "/auth/logout-all" : "/auth/logout");
  } finally {
    sessionEnded();
  }
}

export function errorCode(e: unknown): string {
  const err = e as AxiosError<{ detail?: string }>;
  const detail = err.response?.data?.detail;
  return typeof detail === "string" ? detail : err.response ? "server_error" : "network_error";
}

/** Same rule as the backend's safe_next: only same-site absolute paths. */
export function safeNext(value: string | null | undefined, fallback = "/dashboard"): string {
  if (!value || value.length > 512 || !value.startsWith("/") || value.startsWith("//") || value.includes("\\")) {
    return fallback;
  }
  // eslint-disable-next-line no-control-regex
  return /[\x00-\x20\x7f]/.test(value) ? fallback : value;
}
