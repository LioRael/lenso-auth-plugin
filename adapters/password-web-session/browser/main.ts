// Reuse the existing Auth-owned browser protocol and its cross-tab lock.
// @ts-expect-error The existing owner helper is JavaScript without declarations.
import { createSessionRenewalClient, createSessionValidator, renewalDelay } from "../../../crates/lenso-auth-session-renewal-plugin/browser/session-renewal.mjs";

export type SessionConfig = { csrfCookieName: string; csrfHeaderName?: string; sessionCookieName?: string };
export type SessionMetadata = { session_id: string; expires_at: string; absolute_expires_at: string; renew_after: string };
export type SessionStatus =
  | { status: "active"; metadata: SessionMetadata }
  | { status: "login_required" }
  | { status: "unavailable" };
type SessionState = { authenticated: boolean; metadata?: SessionMetadata };

/** The consumer's authenticated lifecycle owns this scheduler and its cleanup. */
export function startSessionRenewal(config: SessionConfig, onStatus: (status: SessionStatus) => void = () => {}) {
  const validateSession: () => Promise<SessionState> = createSessionValidator();
  let metadata: SessionMetadata | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let active = true;
  let suspended = false;
  let observing: Promise<void> | undefined;
  function resetTimer() { clearTimeout(timer); timer = undefined; }
  function failed() { if (active) { resetTimer(); onStatus({ status: "unavailable" }); } }
  function loginRequired() {
    if (!active) return;
    resetTimer(); metadata = undefined; onStatus({ status: "login_required" });
  }
  function schedule(next: SessionMetadata, retryDelay = 0) {
    if (!active) return;
    resetTimer(); metadata = next; onStatus({ status: "active", metadata: next });
    if (suspended || document.visibilityState !== "visible") return;
    const delay: number | null = renewalDelay(next);
    const expiryDelay = Math.max(0, Date.parse(next.expires_at) - Date.now());
    timer = setTimeout(() => void maintain().catch(failed), Math.max(retryDelay, Math.min(delay ?? expiryDelay, 2_147_483_647)));
  }
  function observe(retryDelay = 0): Promise<void> {
    if (observing) return observing;
    observing = (async () => {
      const current = await validateSession();
      if (!active) return;
      if (current.authenticated && current.metadata) schedule(current.metadata, retryDelay); else loginRequired();
    })().finally(() => { observing = undefined; });
    return observing;
  }
  const renewal = createSessionRenewalClient({
    csrfCookieName: config.csrfCookieName, csrfHeaderName: config.csrfHeaderName,
    validateSession, onLoginRequired: loginRequired, onMetadata: schedule,
  });
  async function maintain() {
    if (!active || suspended || document.visibilityState !== "visible" || !metadata) return;
    const current = metadata;
    const result = await navigator.locks.request("lenso.identity-transition", () => {
      if (!active || suspended || document.visibilityState !== "visible") return;
      return renewal.renewOnce(current);
    });
    if (!active || !result) return;
    if (result.status === "busy") await observe(1000);
    else if (result.status === "too_early") schedule(current, 1000);
    else if (result.status === "failed") failed();
  }
  function visible() {
    resetTimer();
    if (active && !suspended && document.visibilityState === "visible") void observe().catch(failed);
  }
  function pagehide() { suspended = true; resetTimer(); }
  function pageshow(event: PageTransitionEvent) { if (event.persisted) { suspended = false; visible(); } }
  document.addEventListener("visibilitychange", visible);
  window.addEventListener("pagehide", pagehide);
  window.addEventListener("pageshow", pageshow);
  void observe().catch(failed);
  return () => {
    active = false; resetTimer();
    document.removeEventListener("visibilitychange", visible);
    window.removeEventListener("pagehide", pagehide);
    window.removeEventListener("pageshow", pageshow);
  };
}

function csrfToken(name: string) {
  const prefix = `${name}=`;
  return document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix))?.slice(prefix.length);
}
function locked(config: SessionConfig, action: () => Promise<void>): Promise<void> {
  if (!navigator.locks?.request) return Promise.reject(new Error("Browser-wide session locking is required."));
  return navigator.locks.request("lenso.identity-transition", () =>
    navigator.locks.request(`lenso:session-renewal:${config.csrfCookieName}`, action));
}

/** A single explicit logout under the same renewal/login Web Lock. */
export function logoutSession(config: SessionConfig): Promise<void> {
  return locked(config, async () => {
    const csrf = csrfToken(config.csrfCookieName);
    if (!csrf) throw new Error("Current CSRF token required.");
    const response = await fetch("/auth/logout", {
      method: "POST", credentials: "same-origin", cache: "no-store",
      headers: { [config.csrfHeaderName ?? "x-csrf-token"]: csrf },
    });
    if (response.status !== 204) throw new Error("Sign out was not confirmed.");
  });
}

function startLoginForm(form: HTMLFormElement) {
  const identifier = form.querySelector<HTMLInputElement>("#identifier")!;
  const password = form.querySelector<HTMLInputElement>("#password")!;
  const submit = form.querySelector<HTMLButtonElement>("#submit")!;
  const session = document.querySelector<HTMLElement>("#session")!;
  const logout = document.querySelector<HTMLButtonElement>("#logout")!;
  const status = document.querySelector<HTMLElement>("#status")!;
  const config = { csrfCookieName: document.body.dataset.csrfCookie! };
  const validateSession: () => Promise<SessionState> = createSessionValidator();
  let busy = false;
  function message(text: string) { status.textContent = text; }
  function state(next: SessionStatus) {
    if (next.status === "active") {
      form.hidden = true; session.hidden = false; message(`Session active until ${next.metadata.expires_at}.`);
    } else if (next.status === "login_required") {
      form.hidden = false; session.hidden = true; message("Sign in to continue.");
    } else message("Session check is unavailable. Reload before continuing.");
  }
  let cleanup = startSessionRenewal(config, state);
  function pause() { cleanup(); }
  function resume() { cleanup = startSessionRenewal(config, state); }
  async function pending(action: () => Promise<void>) {
    if (busy) return;
    busy = true; submit.disabled = true; logout.disabled = true; pause();
    try { await action(); }
    finally { busy = false; submit.disabled = false; logout.disabled = false; resume(); }
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    const input = { identifier: identifier.value, password: password.value };
    password.value = "";
    void pending(() => locked(config, async () => {
      let response: Response;
      try {
        response = await fetch("/auth/password/login", {
          method: "POST", credentials: "same-origin", cache: "no-store",
          headers: { "content-type": "application/json" }, body: JSON.stringify(input),
        });
      } catch {
        // Delivery may be lost after issuance. Read once; never replay login automatically.
        const current = await validateSession();
        state(current.authenticated && current.metadata ? { status: "active", metadata: current.metadata } : { status: "login_required" });
        message("Login delivery is unknown. Check the session before retrying."); return;
      } finally { input.password = ""; }
      if (response.status !== 200) {
        message(response.status === 409 ? "Sign out before changing identity." : "Sign in was rejected or is unavailable."); return;
      }
      const result: unknown = await response.json();
      if (!result || typeof result !== "object" || "credential" in result ||
          !("authenticated" in result) || result.authenticated !== true ||
          !("expires_at" in result) || typeof result.expires_at !== "string" || !Number.isFinite(Date.parse(result.expires_at))) {
        throw new Error("Invalid login metadata.");
      }
      location.assign("/");
    })).catch(() => message("Login is unavailable. Check the session before retrying."))
      .finally(() => { input.password = ""; });
  });
  logout.addEventListener("click", () => {
    void pending(() => logoutSession(config)).catch(() => message("Sign out was not confirmed. Reload to check the current session."));
  });
  window.addEventListener("pagehide", pause, { once: true });
  window.addEventListener("pageshow", (event) => { if (event.persisted) resume(); });
}

// Importing this module into a Console contribution never starts a form or redirects.
if (typeof document !== "undefined") {
  const form = document.querySelector<HTMLFormElement>("#auth-login");
  if (form) startLoginForm(form);
}
