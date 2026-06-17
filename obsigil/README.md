# obsigil

A mandate-token format and shared-secret **JWT alternative**: a
token split into a public **manifest** and an encrypted
**mandate**, joined by a single separator:

    token = [ manifest ALG ] SEP [ ALG mandate ]

- **manifest** — public claims, readable without a secret
- **mandate** — private claims, sealed under a secret key

Each half is an authenticated, deterministically-encrypted
ciphertext — AES-SIV (RFC 5297, code `0`) or AES-GCM-SIV
(RFC 8452, code `1`) — built directly on RustCrypto. Only
authenticated AEADs are ever compiled in, so an unauthenticated
mandate is structurally unrepresentable.

Verification is symmetric — the same secret [`MandateKey`] both
mints and verifies — so obsigil fits shared-secret (HS256-style)
JWT and JWE use cases, not public-key verification.

The two halves are independent and have disjoint audiences:

- the **mandate** is sealed under a secret 64-byte
  [`MandateKey`] (confidential + authenticated); the front end
  forwards only this half to the backend, which decrypts and
  enforces it;
- the **manifest** is sealed keyless (a public, spec-pinned
  key), giving tamper-evidence only — anyone can read *or
  forge* it, so the front end opens it for UI and treats it as
  advisory.

Nothing binds the halves cryptographically, and nothing needs
to: a forged manifest only misleads the attacker's own UI, while
every backend decision rests on the unforgeable mandate. The
single separator both joins the halves and names the token's
text encoding — `.` for base64url, `~` for lowercase hex — so
the split is unambiguous either way. Either half may be empty,
so a manifest-only (`manifest.`) or mandate-only (`.mandate`)
token is valid.

## Serializations

Each half names its serialization with a sealed one-byte tag:
`j` JSON · `t` TOML · `c` CBOR. JSON is the mandatory default;
TOML and CBOR are behind the `toml` / `cbor` features. The
spec deliberately excludes any format whose decoder can execute
code or build arbitrary objects (e.g. Perl `eval`, YAML
full-load), since the manifest is attacker-forgeable.

## Usage

```rust
use obsigil::{open_manifest, Issuer, Mandate, MandateKey, Manifest, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Access { role: String }

#[derive(Serialize, Deserialize)]
struct Display { theme: String }

// A 64-byte a-tier secret (e.g. from MandateKey::generate()).
let key = MandateKey::from_bytes([42u8; 64])?;

// Issuer: mint a token. The mandate carries the authoritative
// claims; the optional manifest carries advisory ones.
let token = Issuer::new(key)
    .mandate(&Access { role: "admin".into() })
    .exp(4_000_000_000)
    .audience(["api"])
    .subject("u42")
    .manifest("auth.example", &Display { theme: "dark".into() })
    .mint()?;

// Front end: read the manifest, no secret needed (advisory).
let manifest: Manifest<Display> = open_manifest(&token).expect("present");
assert_eq!(manifest.app().theme, "dark");

// Backend: verify the mandate against a candidate key (or
// several — trial decryption picks the one that authenticates).
let key = MandateKey::from_bytes([42u8; 64])?;
let mandate: Mandate<Access> = Verifier::new()
    .key(&key)
    .audience("api")
    .verify(&token)?;
assert_eq!(mandate.app().role, "admin");
```

A verifier enforces the reserved clauses (spec §11): a present
mandate MUST carry `exp` (rejected once `now >= exp`, with
optional leeway) and a UUIDv7 `tid`; a present `aud` is checked
for membership against the verifier's identifier in constant
time. Every rejection collapses to one opaque `Error` — the
granular cause is available via `Error::reason()` for internal
logging only, never to the bearer.

## Status

Pre-1.0; the API may still change before 1.0. The mint/verify
core is complete: reserved-field enforcement (`exp`, `aud`,
`tid`, manifest `iss`), multi-key trial decryption, the
`.`/base64url and `~`/hex text encodings, and JSON/TOML/CBOR
serializations, validated against the cross-language obsigil
test vectors. Built on pre-1.0 RustCrypto AEADs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
