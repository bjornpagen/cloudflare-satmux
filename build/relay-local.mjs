// Loads the built relay artifact into workerd exactly as it would be uploaded: one ES module
// (index.js) and one CompiledWasm module (index_bg.wasm), no bundling.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

// miniflare is resolved from the folder this is run in, where it was installed.
const { Miniflare } = createRequire(`${process.cwd()}/`)("miniflare");

const [dir, port, key, measure, date] = process.argv.slice(2);
const digest = createHash("sha256").update(key).digest("hex");
const mf = new Miniflare({
  host: "127.0.0.1",
  port: Number(port),
  compatibilityDate: date,
  modules: [
    { type: "ESModule", path: "index.js", contents: readFileSync(`${dir}/index.js`, "utf8") },
    { type: "CompiledWasm", path: "index_bg.wasm", contents: readFileSync(`${dir}/index_bg.wasm`) },
  ],
  bindings: {
    SATMUX_RELAY_KEYS: `mac ${digest}\n`,
    SATMUX_RELAY_BUILD: readFileSync(`${dir}/build-id`, "utf8").trim(),
    SATMUX_RELAY_STREAMS: "64",
    SATMUX_RELAY_OPEN_MS: "5000",
    SATMUX_RELAY_CONNECT_MS: "5000",
    SATMUX_RELAY_MEASURE_BYTES: measure,
  },
});
const url = await mf.ready;
console.log(`ready ${url}`);
process.on("SIGTERM", async () => { await mf.dispose(); process.exit(0); });
