// Local-only Task 8 composition cohort. It runs the generated G4 Host in
// Miniflare's embedded workerd with actual D1 bindings. It intentionally
// proves the bounded Web session branch, not a deployed Worker or a
// long-lived stream transport.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { captureWorktreeSnapshot } from "../../workers/oauth-conformance.mjs";

const root = fileURLToPath(new URL(".", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const output = resolve(root, ".fused-session-proof.bundle.mjs");
const require = createRequire(import.meta.url);
const wranglerRequire = createRequire(require.resolve("wrangler/package.json"));
const { Miniflare } = wranglerRequire("miniflare");
const { build } = wranglerRequire("esbuild");
const outputIndex = process.argv.indexOf("--output");

if (outputIndex !== -1 && (outputIndex !== process.argv.length - 2 || !process.argv[outputIndex + 1])) {
  throw new Error("Usage: node qualify-fused-session-workerd.mjs [--output <receipt-path>]");
}
const receiptOutput = outputIndex === -1 ? null : resolve(process.argv[outputIndex + 1]);
if (receiptOutput) {
  const pathFromRepository = relative(repositoryRoot, receiptOutput);
  if (!pathFromRepository.startsWith("..") && !isAbsolute(pathFromRepository)) {
    throw new Error("Fused-session receipt output must be outside the repository worktree");
  }
}

const baseUrl = "https://127.0.0.1";
const proofKey = "local-fused-session-proof-key";
const fixedBindings = {
  PROOF_KEY: proofKey,
  SIGNING_KEY: "0123456789abcdef0123456789abcdef",
  TOKEN_PEPPER: "fedcba9876543210fedcba9876543210",
  OAUTH_KEY: "00112233445566778899aabbccddeeff",
  OIDC_SECRET: "local-proof-oidc-secret-32-bytes!!",
};

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function setCookies(headers) {
  if (typeof headers.getSetCookie === "function") {
    const values = headers.getSetCookie();
    if (values.length) return values;
  }
  const value = headers.get("set-cookie");
  return value ? value.split(/,(?=__Host-[^=]+=)/) : [];
}

function cookie(cookies, name) {
  const value = cookies.find((entry) => entry.startsWith(`${name}=`));
  assert.ok(value, `${name} must be set`);
  return value.split(";", 1)[0];
}

function assertStatus(response, expected, label, lifecycle = true) {
  assert.equal(response.status, expected, `${label} status`);
  if (lifecycle) {
    assert.equal(
      response.headers.get("x-lenso-local-app-lifecycle"),
      "ready-clean",
      `${label} must run one Ready -> clean generated Kernel App`,
    );
  }
}

const source = captureWorktreeSnapshot(repositoryRoot);
const cases = [];
const persistenceDirectory = await mkdtemp(join(tmpdir(), "lenso-auth-fused-session-"));
let mf;

try {
  const buildArgs = ["build.sh"];
  if (process.env.LENSO_CARGO_CONFIG) buildArgs.push("--config", process.env.LENSO_CARGO_CONFIG);
  execFileSync("bash", buildArgs, { cwd: root, stdio: "inherit" });
  await build({
    entryPoints: [resolve(root, "fused-session-proof-worker.mjs")],
    outfile: output,
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    plugins: [
      {
        name: "worker-wasm",
        setup(buildApi) {
          buildApi.onResolve({ filter: /\.wasm$/ }, (args) => ({
            path: args.path,
            external: true,
          }));
        },
      },
    ],
  });

  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const idpJwk = JSON.stringify(privateKey.export({ format: "jwk" }));
  const createLocalWorkerd = () =>
    new Miniflare({
      d1Persist: persistenceDirectory,
      workers: [
        {
          name: "fused-session-main",
          modules: true,
          scriptPath: output,
          modulesRoot: root,
          modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
          compatibilityDate: "2026-07-08",
          d1Databases: {
            ACCOUNT_DB: "fused-session-account-local",
            OAUTH_DB: "fused-session-oauth-local",
          },
          serviceBindings: { IDP: "fused-session-idp" },
          bindings: { ...fixedBindings },
        },
        {
          name: "fused-session-idp",
          modules: true,
          scriptPath: resolve(root, "idp-service-worker.mjs"),
          modulesRoot: root,
          compatibilityDate: "2026-07-08",
          bindings: { ...fixedBindings, IDP_JWK: idpJwk },
        },
      ],
    });
  mf = createLocalWorkerd();
  let accountDb = await mf.getD1Database("ACCOUNT_DB", "fused-session-main");
  let oauthDb = await mf.getD1Database("OAUTH_DB", "fused-session-main");
  let idpWorker = await mf.getWorker("fused-session-idp");

  const request = async (path, options = {}) => {
    const headers = new Headers(options.headers);
    headers.set("x-proof-key", proofKey);
    return mf.dispatchFetch(new URL(path, baseUrl).toString(), {
      ...options,
      headers,
      redirect: options.redirect ?? "manual",
    });
  };
  const run = async (name, assertion) => {
    await assertion();
    cases.push({ name, passed: true });
  };
  const migrate = async (owner) => {
    const response = await request(`/_local/migration?owner=${owner}&action=setup`);
    assertStatus(response, 200, `${owner} migration`, false);
    assert.deepEqual(await response.json(), { ok: true }, `${owner} migration response`);
  };

  await run("owner-migrations-use-event-owned-local-d1-bindings", async () => {
    await migrate("account");
    await migrate("oauth-flow");
  });

  await run("real-ingress-rejects-unauthenticated-business-read", async () => {
    const response = await request("/auth/proof/business/session");
    assertStatus(response, 401, "unauthenticated business read");
    const body = await response.json();
    assert.equal(body.code, "session_required", "business Plugin must own the session rejection");
  });

  let sessionCookie;
  let csrfCookie;
  let callbackUrl;
  await run("oidc-ingress-recovers-to-an-authenticated-business-session", async () => {
    const start = await request(
      "/auth/oidc/start?return_to=%2Fauth%2Fproof%2Fbusiness%2Fsession",
    );
    assertStatus(start, 302, "OIDC start");
    const authorizeUrl = start.headers.get("location");
    assert.ok(authorizeUrl?.startsWith(`${baseUrl}/fixture/authorize?`), "OIDC start must reach the controlled fixture");

    // Browser navigation is dispatched to the separate local workerd service
    // directly. Only the generated OIDC token/JWKS exchange uses the main
    // Worker's HTTP Egress service binding below the Host boundary.
    const authorized = await idpWorker.fetch(authorizeUrl, { redirect: "manual" });
    assert.equal(authorized.status, 302, "controlled fixture authorization status");
    callbackUrl = authorized.headers.get("location");
    assert.ok(callbackUrl?.startsWith(`${baseUrl}/auth/oidc/callback?`), "fixture must issue a same-origin callback");

    const callback = await request(callbackUrl);
    assertStatus(callback, 303, "OIDC callback");
    assert.equal(
      callback.headers.get("location"),
      "/auth/proof/business/session",
      "OIDC callback must preserve the App-local return target",
    );
    const cookies = setCookies(callback.headers);
    assert.equal(cookies.length, 2, "callback must set separate session and CSRF cookies");
    sessionCookie = cookie(cookies, "__Host-session");
    csrfCookie = cookie(cookies, "__Host-csrf");
    assert.ok(cookies.every((value) => value.includes("Secure") && value.includes("SameSite=Lax")), "cookies must retain ingress policy");
    assert.ok(cookies.find((value) => value.startsWith("__Host-session=")).includes("HttpOnly"), "session cookie must be HttpOnly");
    assert.ok(!cookies.find((value) => value.startsWith("__Host-csrf=")).includes("HttpOnly"), "CSRF cookie must remain readable");

    const business = await request("/auth/proof/business/session", {
      headers: { cookie: `${sessionCookie}; ${csrfCookie}` },
    });
    assertStatus(business, 200, "authenticated business read");
    assert.deepEqual(await business.json(), { business: "session-read", authenticated: true }, "business Plugin must receive Router-authenticated session context");
    const oauthRows = await oauthDb.prepare("SELECT COUNT(*) AS count FROM oauth_flows").first();
    const accountRows = await accountDb.prepare("SELECT COUNT(*) AS count FROM auth_sessions").first();
    assert.ok(Number(oauthRows.count) >= 1, "OIDC state must persist through the actual OAuth D1 binding");
    assert.ok(Number(accountRows.count) >= 1, "issued session must persist through the actual Account D1 binding");
  });

  await run("session-recovers-in-a-fresh-local-workerd-from-persisted-d1", async () => {
    await mf.dispose();
    mf = createLocalWorkerd();
    accountDb = await mf.getD1Database("ACCOUNT_DB", "fused-session-main");
    oauthDb = await mf.getD1Database("OAUTH_DB", "fused-session-main");
    idpWorker = await mf.getWorker("fused-session-idp");
    const business = await request("/auth/proof/business/session", {
      headers: { cookie: `${sessionCookie}; ${csrfCookie}` },
    });
    assertStatus(business, 200, "fresh-workerd business read");
    assert.deepEqual(await business.json(), { business: "session-read", authenticated: true }, "persisted App session must authenticate after a fresh generated App");
  });

  await run("replayed-oidc-callback-fails-without-breaking-session", async () => {
    const replay = await request(callbackUrl);
    assertStatus(replay, 400, "replayed OIDC callback");
    const business = await request("/auth/proof/business/session", {
      headers: { cookie: `${sessionCookie}; ${csrfCookie}` },
    });
    assertStatus(business, 200, "business recovery after replay rejection");
  });

  await run("csrf-guarded-logout-revokes-session-and-cleans-up", async () => {
    const cookieHeader = `${sessionCookie}; ${csrfCookie}`;
    const missingCsrf = await request("/auth/logout", {
      method: "POST",
      headers: { cookie: cookieHeader },
    });
    assertStatus(missingCsrf, 403, "logout without CSRF token");
    const stillAuthenticated = await request("/auth/proof/business/session", {
      headers: { cookie: cookieHeader },
    });
    assertStatus(stillAuthenticated, 200, "business recovery after CSRF rejection");

    const logout = await request("/auth/logout", {
      method: "POST",
      headers: { cookie: cookieHeader, "x-csrf-token": csrfCookie.split("=", 2)[1] },
    });
    assertStatus(logout, 204, "CSRF-authorized logout");
    assert.ok(setCookies(logout.headers).every((value) => value.includes("Max-Age=0")), "logout must clear both cookie fields");
    const rejected = await request("/auth/proof/business/session", {
      headers: { cookie: cookieHeader },
    });
    assertStatus(rejected, 401, "revoked session business read");
    const revoked = await accountDb
      .prepare("SELECT COUNT(*) AS count FROM auth_sessions WHERE revoked_at IS NOT NULL")
      .first();
    assert.ok(Number(revoked.count) >= 1, "logout revocation must remain visible in D1");
  });

  const wasmSha256 = sha256(await readFile(resolve(root, "pkg/lenso_workers_g4_host_bg.wasm")));
  // The temporary bundle is intentionally untracked. Remove it before the
  // source-after snapshot so the receipt proves the candidate rather than a
  // build artifact created by the cohort itself.
  await rm(output, { force: true });
  const sourceAfter = captureWorktreeSnapshot(repositoryRoot);
  assert.deepEqual(sourceAfter, source, "fused-session cohort must leave the candidate source unchanged");
  const receipt = {
    schema: "lenso.auth.fused-business-session-local-workerd@1",
    source,
    runtime: "local workerd via Miniflare with actual event-owned D1 bindings",
    wasm_sha256: wasmSha256,
    composition: {
      generated_host_entry: "handle_http",
      resolved_plan_components: [
        "lenso.auth.account",
        "lenso.auth.oauth-flow",
        "lenso.auth.router",
        "lenso.auth.web-session",
        "lenso.auth.oidc-client",
        "proof.business",
        "lenso.web-ingress",
        "lenso.http-egress",
      ],
      session_branch: "real OIDC HTTP ingress -> Account-issued cookie -> Router-authenticated business Plugin -> CSRF logout",
      persistence: "OAuth state and Account sessions use the same request-owned D1 binding scope selected by the generated Host",
      identity_provider_transport:
        "browser navigation is dispatched directly to a separate local Miniflare/workerd IdP service; generated HTTP Egress uses its service binding for OIDC token/JWKS exchange",
    },
    passed: cases.length === 6 && cases.every((entry) => entry.passed),
    cases,
    assertion:
      "One source-pinned generated G4 HTTP plan routed actual ingress requests through a distinct generated business Plugin, OAuth/OIDC Auth, Account session cookies, event-owned D1 persistence, fresh-workerd session recovery, replay rejection, CSRF protection, and logout cleanup.",
    limitations: [
      "Local workerd/Miniflare evidence only; this is not a deployed Worker, Cloudflare D1 target qualification, external identity-provider qualification, or production result.",
      "This cohort proves the Task 8 session branch. It does not prove a long-lived HTTP stream, WebSocket lifecycle, target networking, production retention, or production operational behavior.",
      "The controlled IdP is a credential-free separate local workerd service binding; its synthetic identity is not an external-login claim.",
    ],
  };
  assert.equal(receipt.passed, true, "fused-session cohort must pass every local scenario");
  if (receiptOutput) await writeFile(receiptOutput, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`AUTH_FUSED_SESSION_COHORT_EVIDENCE ${JSON.stringify(receipt)}`);
} finally {
  await mf?.dispose();
  await rm(output, { force: true });
  await rm(persistenceDirectory, { recursive: true, force: true });
}
