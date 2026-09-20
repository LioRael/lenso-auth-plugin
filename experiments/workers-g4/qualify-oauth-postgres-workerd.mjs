// Builds the Auth-owned G4 Wasm Host and executes its PostgreSQL transport
// composition in the locked local `workerd` runtime. Its receipt is designed
// to be consumed by lenso-runtime-rust's temporary cohort wrapper.
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const root = fileURLToPath(new URL(".", import.meta.url));
const output = resolve(root, ".oauth-postgres");
const wasm = "lenso_workers_g4_host_bg.wasm";
const lockedBin = resolve(root, "node_modules/.pnpm/node_modules/.bin");

execFileSync("bash", ["build.sh"], { cwd: root, stdio: "inherit" });
mkdirSync(output, { recursive: true });
copyFileSync(resolve(root, "pkg", wasm), resolve(output, wasm));
execFileSync(
  resolve(lockedBin, "esbuild"),
  [
    "oauth-postgres-workerd.mjs",
    "--bundle",
    "--format=esm",
    "--external:*.wasm",
    "--external:node:*",
    "--outfile=.oauth-postgres/worker.mjs",
  ],
  { cwd: root, stdio: "inherit" },
);
const run = spawnSync(
  resolve(lockedBin, "workerd"),
  ["test", "-I", resolve(root, "node_modules/.pnpm/workerd@1.20260701.1/node_modules"), "oauth-postgres-workerd.capnp"],
  { cwd: root, encoding: "utf8", timeout: 60_000, maxBuffer: 16 * 1024 * 1024 },
);
const log = (run.stdout || "") + (run.stderr || "");
process.stdout.write(log);
const line = log
  .split("\n")
  .find((entry) => entry.startsWith("AUTH_POSTGRES_COHORT_EVIDENCE "));
if (!line || run.status !== 0) {
  throw new Error("Auth OAuth PostgreSQL local-workerd cohort did not emit a passing receipt");
}
const evidence = JSON.parse(line.slice("AUTH_POSTGRES_COHORT_EVIDENCE ".length));
if (!evidence.passed) throw new Error("Auth OAuth PostgreSQL local-workerd cohort failed");
console.log("AUTH_POSTGRES_COHORT_EVIDENCE " + JSON.stringify(evidence));
