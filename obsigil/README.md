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

## Serialization

Both halves are a single canonical CBOR map (RFC 8949 §4.2).
obsigil owns the encoding, so identical fields mint
byte-identical tokens. Reserved fields take negative integer
keys (`tid` is −1, then `exp`, `aud`, `sub`, `iss`); the
non-negative integers and text strings are the application's. A
verifier rejects any non-canonical encoding — unsorted or
duplicate keys, non-shortest integers, indefinite lengths — and
fails closed on an unrecognized negative key.

## Usage

```rust
use obsigil::{claims, Claims, Clauses, Issuer, MandateKey, Verifier};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Access { role: String }

#[derive(Serialize, Deserialize)]
struct Display { theme: String }

// A 64-byte secret (e.g. from generate_key()).
let key = MandateKey::from_bytes([42u8; 64])?;

// Issuer: mint a token. The mandate carries the authoritative
// clauses; the optional manifest carries advisory claims.
let token = Issuer::new(key)
    .clauses(&Access { role: "admin".into() })
    .exp(4_000_000_000)
    .audience(["api"])
    .subject("u42")
    .manifest("auth.example", &Display { theme: "dark".into() })
    .mint()?;

// Front end: read the manifest's claims, no secret needed (advisory).
let advisory: Claims<Display> = claims(&token).expect("present");
assert_eq!(advisory.app().theme, "dark");

// Backend: verify the mandate's clauses against a candidate key (or
// several — trial decryption picks the one that authenticates).
let key = MandateKey::from_bytes([42u8; 64])?;
let mandate: Clauses<Access> = Verifier::new()
    .key(&key)
    .audience("api")
    .clauses(&token)?;
assert_eq!(mandate.app().role, "admin");
```

A verifier enforces the reserved clauses (the Reserved fields section, §8): a present
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
`.`/base64url and `~`/hex text encodings, and canonical-CBOR
fields, validated against the cross-language obsigil test
vectors. Built on pre-1.0 RustCrypto AEADs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
