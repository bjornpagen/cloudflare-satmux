# infra: the relay on Cloudflare

> [!WARNING]
> Read the warning in the [top-level README](../README.md) first. Cloudflare's terms restrict
> using its services to provide a VPN or similar proxy, and deploying this stack may breach the
> agreement on your account. This folder documents how the Workers build is deployed so the
> code can be studied; it is not a recommendation to deploy it. Prefer the native relay on a
> machine you own.

One Alchemy stack (`alchemy.run.ts`) that declares one Worker: the Rust relay, uploaded as
`../build/relay` made it. No wrangler, no bundler, no API token in any file.

## Prerequisites

- Node 26 or newer (it runs `alchemy.run.ts` as TypeScript, unbuilt) and pnpm.
- Rust with the `wasm32-unknown-unknown` target, for `../build/relay` (`../build/README.md`).
- A Cloudflare account. `SATMUX_RELAY_PLAN=paid` needs Workers Paid on it.

## Once

    cd infra
    pnpm install
    cp .env.example .env.local                    # then edit it: every line is required
    pnpm alchemy profile edit --add Cloudflare    # choose OAuth; a browser opens; pick the account

The login is Alchemy's own: it asks for the method (OAuth), the scopes and, if the login reaches
several accounts, which one. The token is kept under `~/.alchemy/` and refreshed there. Nothing
of it enters this repository. `pnpm alchemy profile show` says what is connected.

## Deploy

    pnpm run deploy

That is `../build/relay && alchemy deploy`: it builds the artifact, shows the plan, asks, and
applies. With the artifact already built, `pnpm alchemy deploy` alone does the same, and
`pnpm run plan` only shows the plan. (`pnpm deploy` without `run` is pnpm's own command, not this.)

The stack names `.env.local` itself, so no `--env-file` is passed, and none can be.

The printed `url` must be `https://` followed by `SATMUX_RELAY_NAME`. For a `workers.dev` name
that holds only if the second label is the account's own `workers.dev` subdomain.

## What gets created

- **The relay Worker**, named by the first label of `SATMUX_RELAY_NAME`: the two modules of
  `../build/out/relay` (`index.js`, `index_bg.wasm`) byte for byte, six plain-text variables
  (`SATMUX_RELAY_KEYS`, `_BUILD`, `_STREAMS`, `_OPEN_MS`, `_CONNECT_MS`, `_MEASURE_BYTES`), no
  compatibility flags, Workers Logs off. `SATMUX_RELAY_BUILD` is `../build/out/relay/build-id`.
- **Where it answers**, decided by the name. `<worker>.<subdomain>.workers.dev`: the account's
  `workers.dev` route, no custom domain. Any other name: a custom domain on the zone of the
  account that holds it (the DNS record and certificate are Cloudflare's), `workers.dev` off.
- **The CPU limit**, decided by `SATMUX_RELAY_PLAN`: `paid` sets 300000 ms, the platform's
  maximum; `free` sets none.
- **Alchemy's state store**, on first deploy: a Worker named `alchemy-state-store` in the same
  account, with its token in the account's Secrets Store. It holds this stack's state. Nothing is
  stored in this repository or on AWS.

## The variables

`.env.example` has every one. `SATMUX_RELAY_KEYS` is the list of admitted devices: one
`name digest` per device (a name you choose, the digest `satmux-key` prints), joined with `;` because an env file
holds one line per variable. The stack binds it to the relay as newline-separated lines. A
digest is public. Adding or revoking a device is editing that line and deploying.

A missing or malformed variable fails the plan and names itself, before any credential is used.

## Destroy

    pnpm alchemy destroy

removes the relay and its domain. The state store stays, for other stacks of the account;
`pnpm alchemy state teardown --backend cloudflare` removes it too.

The stage is Alchemy's default, `live_<your user name>`: deploy and destroy as the same user.
