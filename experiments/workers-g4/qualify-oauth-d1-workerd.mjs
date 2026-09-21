// Local-only OAuth/D1 conformance cohort. It uses Miniflare's embedded
// workerd runtime and its actual D1 binding implementation, never a deployed
// Worker or a remote Cloudflare resource.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

import { captureWorktreeSnapshot } from "../../workers/oauth-conformance.mjs";

const root = fileURLToPath(new URL(".", import.meta.url));
const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));
const output = resolve(root, ".oauth-d1-proof.bundle.mjs");
const require = createRequire(import.meta.url);
const wranglerRequire = createRequire(require.resolve("wrangler/package.json"));
const { Miniflare } = wranglerRequire("miniflare");
const { build } = wranglerRequire("esbuild");
const outputIndex = process.argv.indexOf("--output");

if (outputIndex !== -1 && (outputIndex !== process.argv.length - 2 || !process.argv[outputIndex + 1])) {
  throw new Error("Usage: node qualify-oauth-d1-workerd.mjs [--output <receipt-path>]");
}
const receiptOutput = outputIndex === -1 ? null : resolve(process.argv[outputIndex + 1]);
if (receiptOutput) {
  const pathFromRepository = relative(repositoryRoot, receiptOutput);
  if (!pathFromRepository.startsWith("..") && !isAbsolute(pathFromRepository)) {
    throw new Error("OAuth D1 receipt output must be outside the repository worktree");
  }
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function future(minutes = 5) {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function checkOutcome(result, predicate, message) {
  assert.equal(result.ready, true, `${message}: App must reach Ready`);
  assert.equal(result.shutdown, "clean", `${message}: App must shut down cleanly`);
  assert.ok(predicate(result.outcome), `${message}: ${JSON.stringify(result.outcome)}`);
}

async function requireResponseStatus(response, expected, label) {
  if (response.status !== expected) {
    assert.fail(`${label}: ${await response.text()}`);
  }
}

const source = captureWorktreeSnapshot(repositoryRoot);
const cases = [];
const persistenceDirectory = await mkdtemp(join(tmpdir(), "lenso-auth-oauth-d1-"));
let mf;

try {
  const buildArgs = ["build.sh"];
  if (process.env.LENSO_CARGO_CONFIG) {
    buildArgs.push("--config", process.env.LENSO_CARGO_CONFIG);
  }
  execFileSync("bash", buildArgs, { cwd: root, stdio: "inherit" });
  await build({
    entryPoints: [resolve(root, "oauth-d1-proof-worker.mjs")],
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

  const createLocalWorkerd = () =>
    new Miniflare({
      modules: true,
      scriptPath: output,
      modulesRoot: root,
      modulesRules: [{ type: "CompiledWasm", include: ["**/*.wasm"] }],
      compatibilityDate: "2026-07-08",
      d1Databases: {
        ACCOUNT_DB: "oauth-d1-account-local",
        OAUTH_DB: "oauth-d1-local",
      },
      d1Persist: persistenceDirectory,
      bindings: {
        SIGNING_KEY: "local-proof-signing-key",
        TOKEN_PEPPER: "local-proof-token-pepper",
        OAUTH_KEY: "0123456789abcdef0123456789abcdef",
        OIDC_SECRET: "local-proof-oidc-secret",
        OTP_SECRET: "local-proof-otp",
        PROVIDER_SIGNING_KEY: "local-proof-provider-signing",
        PROVIDER_JWKS: "{}",
      },
    });
  mf = createLocalWorkerd();

  let oauthDb = await mf.getD1Database("OAUTH_DB");
  const migration = async (owner, binding) => {
    const response = await mf.dispatchFetch(
      `http://local/migration?owner=${owner}&binding=${binding}&action=setup`,
    );
    await requireResponseStatus(response, 200, `${owner} migration status`);
    assert.deepEqual(await response.json(), { ok: true }, `${owner} migration response`);
  };
  const invoke = async (operation, request, options = {}) => {
    const headers = { "content-type": "application/json" };
    if (options.dropResponseAfterConsume) {
      headers["x-lenso-local-proof-drop-response"] = "after-consume-result";
    }
    const response = await mf.dispatchFetch("http://local/operation", {
      method: "POST",
      headers,
      body: JSON.stringify({ operation, request }),
    });
    if (options.dropResponseAfterConsume) {
      await requireResponseStatus(response, 503, "post-consume response loss status");
      assert.deepEqual(
        await response.json(),
        { error: "host_unavailable" },
        "the caller must not receive the generated consume result",
      );
      return { response_lost_after_durable_consume: true };
    }
    await requireResponseStatus(response, 200, `${operation} status`);
    return response.json();
  };
  const create = async () => {
    const result = await invoke("create", {
      provider: "github",
      return_to: "/settings/security",
      expires_at: future(),
    });
    checkOutcome(result, (outcome) => typeof outcome?.Ok?.state === "string", "create");
    return result.outcome.Ok.state;
  };
  const consume = (state) => invoke("consume", { provider: "github", state });
  const recreateWorkerd = async () => {
    await mf.dispose();
    mf = createLocalWorkerd();
    oauthDb = await mf.getD1Database("OAUTH_DB");
  };

  const run = async (name, assertion) => {
    await assertion();
    cases.push({ name, passed: true });
  };

  await run("owner-migrations-through-event-owned-d1-bindings", async () => {
    await migration("account", "ACCOUNT_DB");
    await migration("oauth-flow", "OAUTH_DB");
  });

  await run("create-persists-through-real-d1", async () => {
    await create();
    const rows = await oauthDb.prepare("SELECT state_digest FROM oauth_flows").all();
    assert.equal(rows.results.length, 1, "OAuth create must persist in the actual D1 binding");
  });

  await run("concurrent-consume-has-one-success", async () => {
    const state = await create();
    const outcomes = await Promise.all([consume(state), consume(state)]);
    const successes = outcomes.filter((result) => result.outcome?.Ok).length;
    const terminalLosers = outcomes.filter(
      (result) => result.outcome?.Err === "already_consumed",
    ).length;
    assert.equal(successes, 1, "exactly one D1-backed consume may succeed");
    assert.equal(terminalLosers, 1, "the other D1-backed consume must be terminal");
    const persisted = await oauthDb
      .prepare("SELECT COUNT(*) AS count FROM oauth_flows WHERE consumed_at IS NOT NULL")
      .first();
    assert.ok(Number(persisted.count) >= 1, "D1 must retain the consumed terminal state");
  });

  await run("post-durable-response-loss-reconciles-through-d1", async () => {
    const state = await create();
    const lost = await invoke(
      "consume",
      { provider: "github", state },
      { dropResponseAfterConsume: true },
    );
    assert.equal(
      lost.response_lost_after_durable_consume,
      true,
      "the proof Host must suppress the generated consume response after it returns",
    );
    const persisted = await oauthDb
      .prepare("SELECT COUNT(*) AS count FROM oauth_flows WHERE consumed_at IS NOT NULL")
      .first();
    assert.ok(
      Number(persisted.count) >= 1,
      "D1 consume must be durable before the application response is withheld",
    );
    const retried = await consume(state);
    checkOutcome(
      retried,
      (outcome) => outcome?.Err === "already_consumed",
      "retry after post-durable response loss",
    );
  });

  await run("revocation-survives-fresh-workerd-and-kernel-app", async () => {
    const state = await create();
    const revoked = await invoke("revoke", { provider: "github", state });
    checkOutcome(revoked, (outcome) => outcome?.Ok !== undefined, "revoke");
    await recreateWorkerd();
    const restarted = await consume(state);
    checkOutcome(restarted, (outcome) => outcome?.Err === "revoked", "consume after workerd restart");
  });

  await run("expired-state-remains-a-domain-result", async () => {
    const state = await create();
    await oauthDb
      .prepare(
        "UPDATE oauth_flows SET created_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','-2 minutes'), expires_at=strftime('%Y-%m-%dT%H:%M:%f000000Z','now','-1 minute') WHERE consumed_at IS NULL AND revoked_at IS NULL",
      )
      .run();
    const expired = await consume(state);
    checkOutcome(expired, (outcome) => outcome?.Err === "expired", "expired consume");
  });

  const sourceAfter = captureWorktreeSnapshot(repositoryRoot);
  assert.deepEqual(sourceAfter, source, "OAuth D1 cohort must leave the candidate source unchanged");
  const receipt = {
    schema: "lenso.auth.oauth-flow-local-d1-cohort@1",
    source,
    runtime: "local workerd via Miniflare with actual event-owned D1 bindings",
    wasm_sha256: sha256(await readFile(resolve(root, "pkg/lenso_workers_g4_host_bg.wasm"))),
    passed: cases.length === 6 && cases.every((entry) => entry.passed),
    cases,
    assertion:
      "OAuth create, concurrent consume, post-durable response-loss reconciliation, revocation across a fresh workerd and Kernel App, expiry, owner migrations, and D1 persistence crossed generated Workers Wasm, Kernel, Capability, and actual local D1 bindings.",
    limitations: [
      "Local workerd/Miniflare evidence only; it is not a deployed Worker, Cloudflare D1 target qualification, or production result.",
      "The response-loss switch is a local proof-host fault, not remote D1 behavior, an external client-disconnect, long-session behavior, or deployment lifecycle qualification.",
    ],
  };
  assert.equal(receipt.passed, true, "OAuth D1 cohort must pass every local scenario");
  if (receiptOutput) await writeFile(receiptOutput, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(`AUTH_D1_COHORT_EVIDENCE ${JSON.stringify(receipt)}`);
} finally {
  await mf?.dispose();
  await rm(output, { force: true });
  await rm(persistenceDirectory, { recursive: true, force: true });
}
