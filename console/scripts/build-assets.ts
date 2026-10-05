import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(import.meta.dir);
const sdk = dirname(dirname(fileURLToPath(import.meta.resolve("@lenso/console-sdk"))));
const result = Bun.spawnSync([process.execPath, join(sdk, "author.mjs"), "build", "--entry", join(root, "console"), "--out", join(root, "dist"), "--plugin-id", "lenso.auth.account.console"], { stdout: "inherit", stderr: "inherit" });
if (result.exitCode !== 0) process.exit(result.exitCode);
const descriptor = JSON.parse(readFileSync(join(root, "dist/descriptor.json"), "utf8"));
mkdirSync(join(root, "dist/assets"), { recursive: true });
for (const asset of descriptor.assets) {
  if (!["workspace.mjs", "workspace.css"].includes(asset.path)) throw new Error("Unexpected Console asset");
  writeFileSync(join(root, "dist/assets", asset.path), Buffer.from(asset.content_base64, "base64"));
}
