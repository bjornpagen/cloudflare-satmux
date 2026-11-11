# cloudflare-satmux

A laptop on a slow, lossy, high-latency link (inflight Wi-Fi is the case it was built for)
keeps a few long-lived connections open to a relay on a well-connected host, and sends every
TCP flow through them as a multiplexed stream. A new connection then costs one message on
a carrier that is already warm, instead of a name lookup, a TCP handshake and a TLS handshake
across the bad link, and the lookup itself happens at the relay.

The relay is one piece of logic with two hosts: a native server, and a WebAssembly build for
the Workers runtime.

> [!WARNING]
> **Educational and research code. Do not use it.**
>
> This repository exists to study a design: multiplexing, flow control, a relay written once
> for two runtimes, a property-tested connection pool. It is not a product, not a service and
> not a VPN, and it is not offered as a way to get around any network's rules.
>
> - **Do not run the relay on Cloudflare's infrastructure.** Cloudflare's terms restrict using
>   its services to provide a VPN or similar proxy. Deploying this to Workers may breach the
>   agreement on your account and get it suspended or closed. The `infra/` stack and the
>   Workers build are here so the code can be read, built and run under a local `workerd`,
>   not as an invitation to deploy them.
> - **Prefer a runtime you own.** `satmux-relay-native` is the same relay logic as a plain
>   server for a machine you control, and the WebAssembly build runs locally under `workerd`
>   (`build/README.md`).
> - **Other people's networks have terms too.** Inflight, hotel, campus and workplace networks
>   commonly prohibit tunnelling and proxying. Whether you may run something like this on a
>   given network, and whether it is lawful where you are, is yours to find out first.
> - **No warranty, no support, no security review.** It has not been audited. It can break
>   your connectivity, misroute traffic, or expose it. The licence disclaims all liability, and
>   so do the authors: anything you do with this code is your own responsibility.
> - **No affiliation.** This project is not affiliated with, endorsed by or sponsored by
>   Cloudflare, Inc. or by any network operator. "Cloudflare" and "Workers" are Cloudflare's
>   trademarks and are used here only to describe what the code targets.
>
> Nothing here is legal advice.

    app ── HTTP CONNECT ──▶ satmuxd ══ carriers: TLS 1.3 + WebSocket + yamux ══▶ relay ──▶ destination
           or a utun                   one per port, kept warm                    (native or wasm)
           tunnel

## How it works

**Carriers.** `satmuxd` holds one carrier per configured port. A carrier is a TCP connection bound to the Wi-Fi interface, TLS 1.3 to the relay's
name, a WebSocket upgrade on `/c` carrying the device key as a bearer token, and
[yamux](https://github.com/hashicorp/yamux/blob/master/spec.md) over the binary messages. The
client is the only side that opens streams. Each carrier is checked with an echo when idle,
marked suspect when the echo is late, replaced on a timer, and drained rather than cut.

**Streams.** The client writes one stream-open and the flow's first bytes in the same flight,
without waiting. The relay answers one status byte and then the destination's bytes. Besides
`Connect` there are four more opens: `Dns` (one DNS-over-HTTPS query, asked by the relay),
`Echo`, and `Source` and `Sink` for measuring. The whole wire format is `crates/satmux-core`,
which both ends link, so they cannot disagree about a byte.

**Verdicts.** A Worker's outbound `connect()` is refused for destinations Cloudflare itself
serves, and the platform gives the same error text for a destination that is forbidden, down,
or does not exist. So when the relay refuses a name, the client tries it directly on a socket
bound to the same interface, and remembers the name as "direct" only if that connect succeeds.
In practice Cloudflare-fronted sites go direct and everything else rides the relay.

**Front ends.** Exactly one per daemon:

- an **HTTP CONNECT proxy** on a loopback port. It answers 200 at once so the client's first
  bytes (a TLS hello) can ride with the open.
- a **tunnel**: a macOS utun interface ended by a userspace TCP/IP stack
  ([smoltcp](https://github.com/smoltcp-rs/smoltcp)). Names are answered with placeholder
  addresses, so the name, not an address, travels with each flow.

**Keys.** A device key is 32 random bytes. The relay holds only SHA-256 digests of the keys it
admits, as a plain Worker variable; without a valid key every path answers 404 with an empty
body.

## Layout

| Crate | What it is |
|---|---|
| `satmux-core` | The wire format: stream-open, status byte, destination, key check. No I/O. |
| `satmux-carrier` | The client engine: configuration, finding the relay without the local resolver, dialing, the carrier pool (a pure state machine, property-tested against a reference model), verdicts, the `Uplink` every front end sends flows through. |
| `satmuxd` | The daemon: the uplink, one front end, the status socket. |
| `satmux-tun` | The tunnel front end. |
| `satmux-relay-logic` | What a relay does with a carrier and each stream, written once over a `Platform` trait. |
| `satmux-relay` | The relay as a Cloudflare Worker (wasm). |
| `satmux-relay-native` | The same logic on tokio: the oracle the Worker is compared against, and what the tests dial. |
| `satmux-probe` | Measures the path to the relay and prints `name value` lines. Changes nothing. |
| `satmux-key`, `satmux-ask`, `satmux-utun` | Make a device key; ask the status socket; open a utun and exec. |

`build/` builds the Worker artifact and `infra/` deploys it; each has its own README.

## Design rules

- **Mechanism only.** No program has a default for any setting: no port, hostname, address
  block, path or timer literal outside tests and the wire format. Each parses its whole
  environment once, at start, into one type whose fields are all required. A missing, unknown
  or malformed setting is exit 100 with one line naming it.
- **Three exits.** 100 bad input (do not restart), 111 temporary failure (restart), 0 asked to
  stop. They are what a supervisor such as s6 or launchd needs and nothing more.
- **State is a sum type.** A flag that selects behaviour is a design error.
- **Tests state properties.** Generated inputs (proptest), compared against a reference where
  one exists; no tables of hand-picked examples, no sleeps, no wall-clock verdicts.
- **The code and its tests are the specification.** There is no separate design document to
  drift from them.

## Build and test

Rust 1.91 or newer (edition 2024).

    cargo build --release
    cargo test --workspace --exclude satmux-relay

`satmux-relay` is excluded because it only builds for wasm; `build/relay` builds it.

## A relay to test against

Read the warning at the top first. For study, run the relay on a machine you own.

    target/release/satmux-key -d 3 > key 3> digest    # the key stays here; the digest is public
    chmod 400 key

`satmux-relay-native` reads only its environment, all of it required: `SATMUX_RELAY_LISTEN`,
either `SATMUX_RELAY_TLS=off` or `SATMUX_RELAY_CERT` with `SATMUX_RELAY_CERT_KEY`,
`SATMUX_RELAY_KEYS` (lines of `<a name> <the digest>`), `SATMUX_RELAY_BUILD`,
`SATMUX_RELAY_STREAMS`, `SATMUX_RELAY_OPEN_MS`, `SATMUX_RELAY_CONNECT_MS`,
`SATMUX_RELAY_MEASURE_BYTES`, `SATMUX_RELAY_DOH` (the DNS-over-HTTPS resolver it asks) and
`SATMUX_RELAY_ALLOW_PRIVATE`. The client insists on TLS 1.3 to `SATMUX_RELAY_NAME` with a
certificate it can verify against `SATMUX_DAEMON_ROOTS`, so give the relay a certificate for
that name and the client the root that signed it.

The WebAssembly build is made by `build/relay` and runs under a local `workerd` as
[`build/README.md`](build/README.md) describes. [`infra/README.md`](infra/README.md) documents
the Workers deployment stack; see the warning before treating it as instructions.

## Run the proxy

Everything is an environment variable and all of them are required. This runs the proxy front
end in the foreground as yourself, with nothing installed:

    mkdir -p run/state
    env -i \
      SATMUX_RELAY_NAME=relay.example.net \
      SATMUX_RELAY_STREAMS=256 \
      SATMUX_RELAY_OPEN_MS=5000 \
      SATMUX_RELAY_CONNECT_MS=10000 \
      SATMUX_RELAY_MEASURE_BYTES=16777216 \
      SATMUX_DAEMON_PORTS="443 8443 2053" \
      SATMUX_DAEMON_RESOLVERS="1.1.1.1 1.0.0.1" \
      SATMUX_DAEMON_DNS_ADDRESS=198.18.0.2 \
      SATMUX_DAEMON_PLACEHOLDERS=198.19.0.0/16 \
      SATMUX_DAEMON_ANSWER_TTL_S=1 \
      SATMUX_DAEMON_PLACEHOLDER_HOLD_S=3600 \
      SATMUX_DAEMON_ECHO_IDLE_MS=15000 \
      SATMUX_DAEMON_SUSPECT_MS=3000 \
      SATMUX_DAEMON_ROTATE_S=600 \
      SATMUX_DAEMON_NO_CARRIER_EXIT_MS=20000 \
      SATMUX_DAEMON_VERDICT_DAYS=30 \
      SATMUX_DAEMON_FIRST_PAYLOAD_MS=10 \
      SATMUX_DAEMON_TUN_MTU=1400 \
      SATMUX_DAEMON_BIND_INTERFACE=en0 \
      SATMUX_DAEMON_KEY="$PWD/key" \
      SATMUX_DAEMON_ROOTS=/etc/ssl/cert.pem \
      SATMUX_DAEMON_STATE="$PWD/run/state" \
      SATMUX_DAEMON_STATUS_SOCKET="$PWD/run/status" \
      SATMUX_DAEMON_PROXY_LISTEN=127.0.0.1:8128 \
      SATMUX_DAEMON_READY_FD=3 \
      target/release/satmuxd 3>/dev/null

Then, in another terminal:

    HTTPS_PROXY=http://127.0.0.1:8128 curl -sI https://github.com
    target/release/satmux-ask run/status status
    target/release/satmux-ask run/status explain github.com

`status` prints each carrier's port, state, round-trip time and age, and counters for flows
relayed, sent direct, replayed, refused and failed. `explain` prints where a name would go now.

Notes on the settings:

- `SATMUX_DAEMON_BIND_INTERFACE` is the interface your default route uses
  (`route -n get default` on macOS).
- `SATMUX_DAEMON_READY_FD` is a descriptor the daemon writes one newline to when the first
  carrier is up, for a supervisor's readiness protocol. It must be open; `3>/dev/null` above
  discards it.
- `SATMUX_DAEMON_STATUS_SOCKET` is a Unix socket path, so it has the platform's length limit
  (about 100 bytes).
- The tunnel front end is selected by giving `SATMUX_DAEMON_UTUN_FD` (an open utun, which
  `satmux-utun` provides) instead of `SATMUX_DAEMON_PROXY_LISTEN`. Routes, the resolver entry
  and the account it runs as are the installer's business, not this repository's.
- `satmux-probe` reads the same variables (without the last four) plus `SATMUX_PROBE_BURST`
  and `SATMUX_PROBE_SECONDS`.

## Status

- The proxy front end and the probe have carried real traffic on macOS. Both relays pass the
  same stream tests; the native one is what the engine's tests dial.
- The tunnel front end is written and tested against stand-ins (its tests drive the same
  packet framing over a socket pair). It has not carried real traffic through a utun.
- Nothing here has had a security review.

## Credit

The idea, and the name, come from [Th0rgal/satmux](https://github.com/Th0rgal/satmux) by
Thomas Marchand (MIT licence): warm multiplexed connections to a ground relay, and sending the
stream-open with the first payload instead of waiting. That project uses a rented VM and its
own framing; this one is an independent implementation in Rust with a relay written for two
runtimes, and TLS, WebSocket and yamux for the carrier.

## Licence

[0BSD](LICENSE). The software is provided "as is", without warranty of any kind, and the author
is not liable for any damages arising from it or from its use.
