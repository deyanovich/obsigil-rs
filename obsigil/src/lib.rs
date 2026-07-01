//! # obsigil
//!
//! A mandate-token format and shared-secret **JWT alternative**: a
//! token split into a public **manifest** and an encrypted
//! **mandate**. Each half is an
//! authenticated, deterministically-encrypted ciphertext — AES-SIV
//! (RFC 5297, code `0`) or AES-GCM-SIV (RFC 8452, code `1`) — joined by a
//! separator that names the text encoding (`.` b64, `~` hex), with a
//! per-half algorithm code in the clear:
//!
//! ```text
//! token = [ manifest ALG ] SEP [ ALG mandate ]
//! ```
//!
//! This crate is the **backend** side: an [`Issuer`] mints mandates under
//! a secret [`MandateKey`], and [`Verifier::clauses`] checks them against the
//! reserved fields (the Reserved fields section, §8). The manifest is keyless and advisory; read
//! its [`claims`] with no secret. Verification is symmetric — the same
//! [`MandateKey`] both mints and verifies — so obsigil fits shared-secret
//! (HS256-style) JWT and JWE use cases, not public-key verification.
//!
//! Built directly on RustCrypto (`aes-siv`, `aes-gcm-siv`, `hkdf`). Only
//! authenticated AEADs are ever compiled in, so an unauthenticated mandate
//! is structurally unrepresentable (the mandate-must-be-authenticated rule of the Security Considerations, §16.2).
//!
//! The normative format is the obsigil specification; section references in
//! this source (e.g. the manifest construction, §5.2) point there.
//!
//! # Example
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use obsigil::{claims, generate_key, Claims, Clauses, Issuer, MandateKey, Verifier};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct ClauseData { role: String }
//! #[derive(Serialize, Deserialize)]
//! struct ClaimData { theme: String }
//!
//! // One secret key as hex, provisioned to both sides. `generate_key()`
//! // returns 128 lowercase hex digits (§6.2) to store as a secret (e.g. an
//! // environment variable); load it with `MandateKey::from_hex`.
//! let key_hex = generate_key();
//! let issuer_key = MandateKey::from_hex(&key_hex)?;
//!
//! // Issuer: mint a token. The mandate carries the authoritative clauses;
//! // the optional manifest carries advisory claims.
//! let token = Issuer::new(issuer_key)
//!     .clauses(&ClauseData { role: "admin".into() })
//!     .exp(4_000_000_000)
//!     .audience(["api"])
//!     .manifest("auth.example", &ClaimData { theme: "dark".into() })
//!     .mint()?;
//!
//! // Front end: read the manifest's claims with no secret (advisory only).
//! let advisory: Claims<ClaimData> = claims(&token).expect("present");
//! assert_eq!(advisory.issuer(), "auth.example");
//!
//! // Backend: verify the mandate's clauses (authoritative). `now` is pinned
//! // here for a deterministic example; omit it to read the system clock.
//! let verify_key = MandateKey::from_hex(&key_hex)?;
//! let clauses: Clauses<ClauseData> = Verifier::new()
//!     .key(&verify_key)
//!     .audience("api")
//!     .now(1_000_000_000)
//!     .clauses(&token)?;
//! assert_eq!(clauses.app().role, "admin");
//! # Ok(()) }
//! ```

mod aead;
mod encoding;
mod error;
mod key;
mod mint;
mod reserved;
mod serial;
mod token;
mod types;
mod verify;

#[cfg(feature = "conformance")]
pub mod lowlevel;

pub use error::{Error, KeyError, MintError, Reason};
pub use key::{generate_key, MandateKey};
pub use mint::{Issuer, MintBuilder};
pub use reserved::{Claims, Clauses, NoApp};
pub use types::{tid_issued_at, Alg, Encoding, NumericDate, MANIFEST_KEY};
pub use verify::{authorization_header, claims, mandate, manifest, manifest_plaintext, Verifier};

// Re-exported for callers handling `tid` (the `tid` field, §8.2).
pub use uuid::Uuid;
