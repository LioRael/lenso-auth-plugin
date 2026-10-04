import test from "node:test";
import assert from "node:assert/strict";
import { createSessionRenewalClient, createSessionValidator, renewalDelay } from "./session-renewal.mjs";

const now = Date.parse("2026-10-04T01:00:00Z");
const metadata = { expires_at: "2026-10-04T02:00:00Z", renew_after: "2026-10-04T00:59:00Z" };
const next = { session_id: "ses_synthetic", expires_at: "2026-10-04T03:00:00Z",
  absolute_expires_at: "2026-10-05T01:00:00Z", renew_after: "2026-10-04T01:10:00Z" };
const locks = { request: async (_name, options, body) => {
  assert.deepEqual(options, { ifAvailable: true }); return body({});
} };
function setup(status, code, authenticated = true) {
  const seen = { fetch: 0, validate: 0, login: 0, metadata: [] };
  const client = createSessionRenewalClient({ csrfCookieName: "__Host-csrf", now: () => now, locks,
    readCsrfToken: () => "current-synthetic-csrf",
    fetchImpl: async (url, options) => {
      seen.fetch++; assert.equal(url, "/auth/session/renew"); assert.equal(options.method, "POST");
      assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store");
      assert.equal(options.headers["x-csrf-token"], "current-synthetic-csrf");
      assert.equal(options.body, undefined);
      if (status === "lost") throw new Error("synthetic response loss");
      return { status, json: async () => status === 200 ? next : { code } };
    },
    validateSession: async () => { seen.validate++; return { authenticated, metadata: authenticated ? next : undefined }; },
    onLoginRequired: () => { seen.login++; }, onMetadata: (value) => seen.metadata.push(value),
  });
  return { client, seen };
}
test("success exposes metadata and same-tab requests share one attempt", async () => {
  const { client, seen } = setup(200);
  const first = client.renewOnce(metadata), second = client.renewOnce(metadata);
  assert.equal(first, second); assert.equal((await first).status, "renewed");
  assert.equal(seen.fetch, 1); assert.equal(seen.validate, 0); assert.equal(seen.login, 0);
  assert.deepEqual(seen.metadata, [next]);
});
test("stale winner validation runs once with no renewal loop or logout", async () => {
  const { client, seen } = setup(409, "stale_credential");
  assert.equal((await client.renewOnce(metadata)).status, "validated");
  assert.equal(seen.fetch, 1); assert.equal(seen.validate, 1); assert.equal(seen.login, 0);
});
test("response loss requires login only when one read-only validation fails", async () => {
  const { client, seen } = setup("lost", undefined, false);
  assert.equal((await client.renewOnce(metadata)).status, "login_required");
  assert.equal(seen.fetch, 1); assert.equal(seen.validate, 1); assert.equal(seen.login, 1);
});
test("revoked sessions require login and unavailable renewal does not clear session", async () => {
  const revoked = setup(401, "session_revoked");
  assert.equal((await revoked.client.renewOnce(metadata)).status, "login_required");
  assert.equal(revoked.seen.login, 1); assert.equal(revoked.seen.validate, 0);
  const unavailable = setup(409, "managed_renewal_unavailable");
  assert.equal((await unavailable.client.renewOnce(metadata)).status, "failed");
  assert.equal(unavailable.seen.login, 0); assert.equal(unavailable.seen.validate, 0);
});
test("another tab holding Web Lock prevents a second provider request", async () => {
  let calls = 0;
  const client = createSessionRenewalClient({ csrfCookieName: "__Host-csrf", validateSession: async () => ({}),
    locks: { request: async (_name, _options, body) => body(null) },
    fetchImpl: async () => { calls++; throw new Error("must not call"); }, now: () => now });
  assert.equal((await client.renewOnce(metadata)).status, "busy"); assert.equal(calls, 0);
});
test("final session expiry and too-early metadata do not start renewal", async () => {
  const { client, seen } = setup(200);
  assert.equal((await client.renewOnce({ ...metadata, renew_after: next.renew_after })).status, "too_early");
  assert.equal(seen.fetch, 0);
  assert.equal(renewalDelay({ ...metadata, renew_after: metadata.expires_at }, now), null);
  assert.equal(renewalDelay(metadata, now), 0);
});
test("requires browser-wide locks instead of silently falling back to per-tab ownership", () => {
  assert.throws(() => createSessionRenewalClient({ csrfCookieName: "__Host-csrf", validateSession: () => {},
    fetchImpl: () => {}, locks: null }), /browser-wide/);
});

test("default stale validation makes exactly one state GET and never replays POST", async () => {
  const requests = [];
  let login = 0;
  const client = createSessionRenewalClient({ csrfCookieName: "__Host-csrf", locks, now: () => now,
    readCsrfToken: () => "synthetic-csrf", onLoginRequired: () => login++,
    fetchImpl: async (url, options) => {
      requests.push([url, options.method]);
      assert.equal(options.credentials, "same-origin");
      if (options.method === "POST") return { status:409, json: async () => ({code:"stale_credential"}) };
      assert.equal(options.cache,"no-store"); assert.equal(options.body,undefined);
      return { status:200, json: async () => ({authenticated:true,...next}) };
    },
  });
  const result = await client.renewOnce(metadata);
  assert.equal(result.status,"validated"); assert.deepEqual(result.metadata,next);
  assert.equal(login,0);
  assert.deepEqual(requests, [["/auth/session/renew","POST"],["/auth/session/state","GET"]]);
});

test("initial state validator returns metadata without choosing any credential", async () => {
  let calls = 0;
  const validate = createSessionValidator(async (url, options) => {
    calls++; assert.equal(url,"/auth/session/state"); assert.equal(options.method,"GET");
    assert.equal(options.body,undefined); assert.equal(options.headers,undefined);
    return { status:200, json:async () => ({authenticated:true,...next}) };
  });
  assert.deepEqual(await validate(), {authenticated:true,metadata:next});
  assert.equal(calls,1);
  const expired = createSessionValidator(async () => ({status:401}));
  assert.deepEqual(await expired(), {authenticated:false});
  const unavailable = createSessionValidator(async () => ({status:503}));
  await assert.rejects(unavailable(), /unavailable/);
});
