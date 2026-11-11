import * as Cloudflare from "@alchemy.run/cloudflare"
import * as Alchemy from "alchemy"
import { Config, ConfigProvider, Effect, FileSystem, String as Str } from "effect"
import { ARTIFACT } from "#artifact.ts"
import { RELAY, type Hosting } from "#env.ts"

/** The most CPU a paid Worker may be given per invocation, in milliseconds: five minutes, the
 * platform's ceiling. A carrier is one long invocation, so it takes all of it. */
const PAID_CPU_MS = 300_000

/** What each plan lets the stack ask for. */
const LIMITS = {
	free: {},
	paid: { limits: { cpuMs: PAID_CPU_MS } }
} as const

/** Where the relay answers, as Worker properties. `domain: null` detaches any custom domain, so
 * moving a relay back to `workers.dev` leaves none behind. */
const addressOf = (hosting: Hosting) =>
	hosting.kind === "workers-dev"
		? ({ name: hosting.script, workersDev: true, domain: null } as const)
		: ({ name: hosting.script, workersDev: false, domain: hosting.hostname } as const)

/** The identifier of the artifact on disk. Its absence means the relay was never built here. */
const buildId = Effect.gen(function* () {
	const fs = yield* FileSystem.FileSystem
	return yield* fs.readFileString(ARTIFACT.buildId).pipe(
		Effect.map(Str.trim),
		Effect.mapError(
			(cause) =>
				new Config.ConfigError(
					new ConfigProvider.SourceError({
						message: `no relay artifact at ${ARTIFACT.buildId}: run ../build/relay (pnpm run deploy does)`,
						cause
					})
				)
		)
	)
})

/**
 * The relay: the Rust build's two files uploaded byte for byte, with the variables the relay
 * says it reads, all plain text. Nothing here is a secret: the keys are digests.
 */
const relay = Effect.gen(function* () {
	const env = yield* RELAY
	const build = yield* buildId
	return {
		...addressOf(env.hosting),
		...LIMITS[env.plan],
		main: ARTIFACT.entry,
		bundle: false,
		rules: [{ globs: ["**/*.js"] }, { globs: ["**/*.wasm"], type: "CompiledWasm" as const }],
		compatibility: { date: env.compatibilityDate, flags: [] },
		observability: { enabled: false },
		env: {
			SATMUX_RELAY_KEYS: env.keys,
			SATMUX_RELAY_BUILD: build,
			SATMUX_RELAY_STREAMS: env.streams,
			SATMUX_RELAY_OPEN_MS: env.openMs,
			SATMUX_RELAY_CONNECT_MS: env.connectMs,
			SATMUX_RELAY_MEASURE_BYTES: env.measureBytes
		}
	}
})

/**
 * One stack, one Worker. Credentials are the operator's Alchemy profile, and the stack's state is
 * kept by a small Worker in the same Cloudflare account, so Cloudflare is the only party.
 * `.env.local` is named here, so a bare `alchemy deploy` reads it.
 */
export default Alchemy.Stack(
	"cloudflare-satmux",
	{
		providers: Cloudflare.providers(),
		state: Cloudflare.state(),
		secrets: Alchemy.Secrets.DotEnv({ path: ".env.local" })
	},
	Effect.gen(function* () {
		const worker = yield* Cloudflare.Worker("Relay", relay)
		return { url: worker.url }
	})
)
