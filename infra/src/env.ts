import { Array as Arr, Config, Effect, Schema, String as Str } from "effect"

/** A count or a number of milliseconds or bytes, kept as the decimal text the relay parses: a
 * Worker variable is text, and a number bound as JSON would reach the relay as something else. */
const Quantity = Schema.String.check(Schema.isPattern(/^[1-9][0-9]*$/))

/** A Cloudflare compatibility date. */
const CompatibilityDate = Schema.String.check(Schema.isPattern(/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/))

/** One `name sha256-hex` line: a device's name and the digest `satmux-key` prints. */
const KeyLine = Schema.String.check(Schema.isPattern(/^[A-Za-z0-9._-]+ [0-9a-f]{64}$/))

/**
 * The key lines. An env file holds one line per variable, so the lines are joined with `;` there
 * and the relay is bound the newline-separated text it parses. At least one line is required: a
 * relay with no key admits nobody, and deploying that is a mistake, not a configuration.
 */
const keys = Config.schema(Schema.NonEmptyString, "SATMUX_RELAY_KEYS").pipe(
	Config.map((text) => Arr.map(Str.split(text, ";"), Str.trim)),
	Config.mapEffect((lines) =>
		Schema.decodeUnknownEffect(Schema.NonEmptyArray(KeyLine))(lines).pipe(
			Effect.mapError((refused) => new Config.ConfigError(refused))
		)
	),
	Config.map(Arr.join("\n"))
)

/** Where the relay answers. The name decides it: a `workers.dev` name is the account's own
 * subdomain and needs no zone; any other name is a custom domain on a zone of the account. */
export type Hosting =
	| { readonly kind: "workers-dev"; readonly script: string; readonly subdomain: string }
	| { readonly kind: "custom-domain"; readonly script: string; readonly hostname: string }

const WorkersDevName = Schema.TemplateLiteralParser([
	Schema.String.check(Schema.isPattern(/^[a-z0-9][a-z0-9-]*$/)),
	".",
	Schema.String.check(Schema.isPattern(/^[a-z0-9][a-z0-9-]*$/)),
	".workers.dev"
])

const CustomDomainName = Schema.String.check(
	Schema.isPattern(/^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$/),
	Schema.makeFilter((name: string) => !Str.endsWith(".workers.dev")(name), {
		expected: "a name outside workers.dev, or exactly <worker>.<subdomain>.workers.dev"
	})
)

/** The Worker's script is named by the hostname's first label in both variants, which is what
 * `workers.dev` requires and what keeps the two from disagreeing. */
const hosting = Config.schema(
	Schema.Union([WorkersDevName, CustomDomainName]),
	"SATMUX_RELAY_NAME"
).pipe(
	Config.map(
		(name): Hosting =>
			typeof name === "string"
				? { kind: "custom-domain", script: Str.split(name, ".")[0], hostname: name }
				: { kind: "workers-dev", script: name[0], subdomain: name[2] }
	)
)

/** The account's Workers plan. Free allows 10 ms of CPU per invocation and takes no limit; paid
 * takes the limit the stack sets. */
const plan = Config.schema(Schema.Literals(["free", "paid"]), "SATMUX_RELAY_PLAN")

/** Every variable the stack reads. Each is required and none has a default: they are copied from
 * `.env.example` into `.env.local`, and a missing or malformed one fails the plan by name. */
export const RELAY = Config.all({
	hosting,
	plan,
	keys,
	compatibilityDate: Config.schema(CompatibilityDate, "SATMUX_RELAY_COMPATIBILITY_DATE"),
	streams: Config.schema(Quantity, "SATMUX_RELAY_STREAMS"),
	openMs: Config.schema(Quantity, "SATMUX_RELAY_OPEN_MS"),
	connectMs: Config.schema(Quantity, "SATMUX_RELAY_CONNECT_MS"),
	measureBytes: Config.schema(Quantity, "SATMUX_RELAY_MEASURE_BYTES")
})
