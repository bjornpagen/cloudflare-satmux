# The relay artifact

`build/relay` (POSIX sh; the same on macOS and Linux) builds `crates/satmux-relay` and leaves:

    build/out/relay/index.js         the entry: an ES module, already bundled and minified
    build/out/relay/index_bg.wasm    the WebAssembly, imported by index.js as `./index_bg.wasm`
    build/out/relay/build-id         `git rev-parse HEAD`, or `dev` outside a git checkout

Upload exactly these two modules, with no bundling step:

| module name     | type                         |
|-----------------|------------------------------|
| `index.js`      | ES module, the main module   |
| `index_bg.wasm` | CompiledWasm                 |

The wasm must be named `index_bg.wasm` and sit beside the entry, because `index.js` imports it
by that relative name. `index.js` also imports `cloudflare:sockets` and `cloudflare:workers`,
which the runtime provides.

Compatibility: no compatibility flags. Run under workerd 1.20260730.1 with compatibility dates
2025-01-01 and 2026-08-06 (the newest that binary knows); both pass. `nodejs_compat` is not needed.

The Worker reads six plain variables, all required (a missing or refused one answers 500 with
an empty body and logs one line naming it):

    SATMUX_RELAY_KEYS  SATMUX_RELAY_BUILD  SATMUX_RELAY_STREAMS
    SATMUX_RELAY_OPEN_MS  SATMUX_RELAY_CONNECT_MS  SATMUX_RELAY_MEASURE_BYTES

`SATMUX_RELAY_BUILD` is meant to be the content of `build-id`. `SATMUX_RELAY_STREAMS` must be
at least 1; yamux is given room for twice that many streams (256 KiB of window each).

## What the build needs

Rust with the `wasm32-unknown-unknown` target, and network on first use: the script installs
`worker-build` 0.8.7 into `build/tools` (`cargo install --locked`), and `worker-build` itself
downloads `wasm-bindgen` 0.2.130, `wasm-opt` 132 and `esbuild` 0.28.2 into the user's cache
folder (`~/.cache/worker-build` on Linux; on macOS the platform's cache folder, not checked here). After one
successful run it builds offline. No wrangler, no node.

`worker-build` warns that `strip = true` hides the wasm's `target_features` section. The
artifact built that way is the one that was tested.

## Running the artifact locally

`build/relay-local.mjs` loads the two modules into workerd through miniflare, the way an
upload would, with the variables set:

    npm install miniflare          # in any scratch folder; then, from it:
    node /path/to/build/relay-local.mjs /path/to/build/out/relay 18787 <key> 1000000 2026-08-06
    cargo run -p satmux-relay-native --example drive -- 127.0.0.1:18787 <key> 1000000

`drive` prints one `name value` line per exchange. Run against the native relay
(`SATMUX_RELAY_ALLOW_PRIVATE=yes`) it prints the same lines, except where the platforms differ:

    connect-closed-port   native: Unreachable   workerd: Forbidden

workerd rejects a connect to a closed loopback port with `proxy request failed, cannot connect
to the specified address`, the text Cloudflare also uses for addresses it refuses. See
`status_of_refusal` in `crates/satmux-relay/src/lib.rs`.
