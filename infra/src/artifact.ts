/**
 * What `../build/relay` leaves behind, relative to this package: the JavaScript entry module, the
 * `.wasm` beside it, and the build identifier the relay answers `GET /v` with. The one place the
 * stack names the artifact's layout.
 */
export const ARTIFACT = {
	entry: "../build/out/relay/index.js",
	buildId: "../build/out/relay/build-id"
} as const
