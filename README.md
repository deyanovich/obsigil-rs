# obsigil-rs

Rust implementation of **obsigil**, a mandate-token format: a
JWS/JWE-style token split into a public manifest and an
encrypted mandate. Each half is an authenticated,
deterministically-encrypted ciphertext — AES-SIV (RFC 5297) or
AES-GCM-SIV (RFC 8452) — built directly on RustCrypto.

Sealing is two-layer: a secret-keyed mandate and a keyless,
tamper-evident manifest. Claim serializations are JSON, TOML,
and CBOR, per half. The spec deliberately omits any format
whose decoder can execute code or build arbitrary objects (Perl
`eval`, YAML full-load), since the manifest is
attacker-forgeable. See the obsigil spec for the authoritative
format definition.

## Layout

- [`obsigil/`](obsigil/) — the `obsigil` library crate.
