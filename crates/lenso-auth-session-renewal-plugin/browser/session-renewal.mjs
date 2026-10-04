/**
 * One explicit renewal attempt. The owning application schedules active-session
 * calls from server metadata and supplies its existing read-only session check.
 * This module never reads the HttpOnly session credential or writes Cookies.
 */
export function createSessionRenewalClient({
  csrfCookieName,
  csrfHeaderName = "x-csrf-token",
  validateSession,
  onLoginRequired = () => {},
  onMetadata = () => {},
  fetchImpl = globalThis.fetch,
  locks = globalThis.navigator?.locks,
  readCsrfToken = () => readCookie(csrfCookieName),
  now = Date.now,
}) {
  validateSession ??= createSessionValidator(fetchImpl);
  if (!/^__Host-[A-Za-z0-9_-]+$/.test(csrfCookieName ?? "") ||
      !/^[A-Za-z0-9-]+$/.test(csrfHeaderName) ||
      typeof validateSession !== "function" || typeof fetchImpl !== "function" ||
      typeof locks?.request !== "function") {
    throw new TypeError("Renewal requires configured CSRF, a session validator and browser-wide Web Locks.");
  }
  let pending;
  const lockName = `lenso:session-renewal:${csrfCookieName}`;

  async function validateOnce(reason) {
    // This is a read-only validation, never a renewal or business retry.
    const current = await validateSession();
    if (current?.authenticated === true) {
      if (current.metadata) onMetadata(current.metadata);
      return { status: "validated", reason, metadata: current.metadata };
    }
    onLoginRequired(reason);
    return { status: "login_required", reason };
  }

  async function attempt(metadata) {
    const expiry = Date.parse(metadata?.expires_at);
    const after = Date.parse(metadata?.renew_after);
    if (!Number.isFinite(expiry) || !Number.isFinite(after)) {
      throw new TypeError("Managed server renewal metadata is required.");
    }
    if (expiry <= now()) {
      // Another tab may have rotated the shared Cookie while this tab missed
      // its metadata update. Only the server can decide whether it expired.
      return validateOnce("session_metadata_expired");
    }
    if (after > now()) return { status: "too_early", renew_after: metadata.renew_after };
    const csrf = readCsrfToken();
    if (!csrf) throw new Error("The current CSRF Cookie is required.");
    let response;
    try {
      response = await fetchImpl("/auth/session/renew", {
        method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { [csrfHeaderName]: csrf },
      });
    } catch {
      // A response can be lost after the server commits. Validate once; there is
      // no plaintext escrow and an old/stale Cookie then requires login.
      return validateOnce("renewal_delivery_unknown");
    }
    if (response.status === 200) {
      let next;
      try { next = await response.json(); } catch {
        return validateOnce("renewal_delivery_unknown");
      }
      if (!Number.isFinite(Date.parse(next?.expires_at)) ||
          !Number.isFinite(Date.parse(next?.absolute_expires_at)) ||
          !Number.isFinite(Date.parse(next?.renew_after)) || "credential" in next) {
        throw new Error("Invalid non-sensitive renewal metadata.");
      }
      onMetadata(next);
      return { status: "renewed", metadata: next };
    }
    let problem;
    try { problem = await response.json(); } catch { problem = {}; }
    // RFC 9457 extensions may expose code directly; type identifies it otherwise.
    const code = problem.code ?? problem.type?.split("/").pop();
    if (response.status === 409 && code === "stale_credential") {
      return validateOnce("stale_credential");
    }
    if (response.status === 401) {
      onLoginRequired(code ?? "session_rejected");
      return { status: "login_required", reason: code ?? "session_rejected" };
    }
    if (response.status === 429) return { status: "too_early", renew_after: metadata.renew_after };
    return { status: "failed", http_status: response.status, code };
  }

  return {
    renewOnce(metadata) {
      if (pending) return pending;
      pending = locks.request(lockName, { ifAvailable: true }, (lock) =>
        lock ? attempt(metadata) : { status: "busy" })
        .finally(() => { pending = undefined; });
      return pending;
    },
  };
}

/** Read-only same-origin managed metadata, including the initial login state. */
export function createSessionValidator(fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") throw new TypeError("A fetch implementation is required.");
  return async () => {
    const response = await fetchImpl("/auth/session/state", {
      method: "GET", credentials: "same-origin", cache: "no-store",
    });
    if (response.status === 401 || response.status === 409) return { authenticated: false };
    if (response.status !== 200) throw new Error("Managed session validation is unavailable.");
    const current = await response.json();
    if (current?.authenticated !== true || typeof current.session_id !== "string" || !current.session_id ||
        !Number.isFinite(Date.parse(current.expires_at)) ||
        !Number.isFinite(Date.parse(current.absolute_expires_at)) ||
        !Number.isFinite(Date.parse(current.renew_after)) || "credential" in current) {
      throw new Error("Invalid non-sensitive managed session state.");
    }
    return { authenticated: true, metadata: {
      session_id: current.session_id, expires_at: current.expires_at,
      absolute_expires_at: current.absolute_expires_at, renew_after: current.renew_after,
    } };
  };
}

function readCookie(name) {
  const prefix = `${name}=`;
  const cookie = globalThis.document?.cookie.split(";").map((s) => s.trim())
    .find((s) => s.startsWith(prefix));
  return cookie ? cookie.slice(prefix.length) : undefined;
}

/** null means no further renewal fits; the application must observe expiry. */
export function renewalDelay(metadata, now = Date.now()) {
  const expiry = Date.parse(metadata?.expires_at);
  const after = Date.parse(metadata?.renew_after);
  if (!Number.isFinite(expiry) || !Number.isFinite(after)) throw new TypeError("Invalid renewal metadata.");
  if (after >= expiry || expiry <= now) return null;
  return Math.max(0, after - now);
}
