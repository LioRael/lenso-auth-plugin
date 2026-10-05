import { startSessionRenewal } from "../../adapters/password-web-session/browser/main";

declare const LENSO_SESSION_CONFIG: null | { csrfCookieName: string; csrfHeaderName: string };
type SessionStatus = { status: "active" | "login_required" | "unavailable"; metadata?: unknown };
export const apiMajor = 1;

// The existing Console global contribution lifecycle owns suspension/disposal.
// Account and the existing renewal adapter retain all session authority/state.
export function createWorkspace(runtime: { react: typeof import("react") }) {
  const React = runtime.react;
  function Page({ suspended, signal }: { suspended: boolean; signal: AbortSignal }) {
    const [current, setCurrent] = React.useState<SessionStatus | null>(null);
    React.useEffect(() => {
      if (!LENSO_SESSION_CONFIG || suspended || signal.aborted) return;
      const stop = startSessionRenewal(LENSO_SESSION_CONFIG, setCurrent);
      signal.addEventListener("abort", stop, { once: true });
      return () => { signal.removeEventListener("abort", stop); stop(); };
    }, [suspended, signal]);
    if (!LENSO_SESSION_CONFIG || suspended || !current) return null;
    const text = current.status === "active" ? "Session active" : current.status === "login_required" ? "Sign in to continue" : "Session check unavailable";
    return React.createElement("aside", { "aria-label": "Session", style: { display: "flex", gap: "12px", alignItems: "center", padding: "8px 16px", flexWrap: "wrap" } },
      React.createElement("span", { role: "status" }, text),
      React.createElement("a", { href: "/auth/login", style: { color: "inherit" } }, current.status === "login_required" ? "Sign in" : "Manage this session"));
  }
  return { Page };
}
