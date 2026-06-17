# obsigil-rs

Rust implementation of **obsigil**, a mandate-token format and
shared-secret **JWT alternative**: a token split into a public,
advisory manifest and a secret-sealed, authoritative mandate.
Each half is an authenticated, deterministically-encrypted
ciphertext — AES-SIV (RFC 5297) or AES-GCM-SIV (RFC 8452) —
built directly on RustCrypto.

Verification is symmetric: the verifier holds the same key that
mints, so obsigil fits shared-secret (HS256-style) JWT and JWE
use cases, not public-key verification.

Sealing is two-layer: a secret-keyed mandate and a keyless,
tamper-evident manifest. Claim serializations are JSON, TOML,
and CBOR, per half. The spec deliberately omits any format
whose decoder can execute code or build arbitrary objects (Perl
`eval`, YAML full-load), since the manifest is
attacker-forgeable. See the obsigil spec for the authoritative
format definition.

## Layout

- [`obsigil/`](obsigil/) — the `obsigil` library crate.
