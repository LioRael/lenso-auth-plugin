import { mkdir } from "node:fs/promises";
await mkdir("dist", { recursive: true });
const result = await Bun.build({ entrypoints: ["browser/session-global.ts"], target: "browser", format: "esm", minify: false });
if (!result.success || result.outputs.length !== 1) throw new Error("Auth session surface compilation failed");
await Bun.write("dist/session.mjs", result.outputs[0]);
