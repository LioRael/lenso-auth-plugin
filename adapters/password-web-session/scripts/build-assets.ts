import { mkdir } from "node:fs/promises";
await mkdir("dist", { recursive: true });
const result = await Bun.build({ entrypoints: ["browser/main.ts"], target: "browser", format: "esm", minify: false });
if (!result.success || result.outputs.length !== 1) throw new Error("Auth browser asset compilation failed");
await Bun.write("dist/assets.js", result.outputs[0]);
