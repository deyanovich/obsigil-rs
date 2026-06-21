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
tamper-evident manifest. Each half's fields are a single
canonical CBOR map (RFC 8949 §4.2) — obsigil's reserved fields
at negative integer keys, application data at non-negative
integer and text-string keys. See the obsigil spec for the
authoritative format definition.

## Layout

- [`obsigil/`](obsigil/) — the `obsigil` library crate.
- [`obsigil-cli/`](obsigil-cli/) — the `obsigil` command-line tool
  (mint, verify, open-manifest, forward, and the byte-level
  conformance ops).
