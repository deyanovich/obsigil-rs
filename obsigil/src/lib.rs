//! # obsigil
//!
//! A mandate-token format: a JWT-like token split into a public
//! **manifest** and an encrypted **mandate**. Each half is an
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
//! a secret [`MandateKey`], and [`Verifier::verify`] checks them against the
//! reserved fields (spec §11). The manifest is keyless and advisory; open
//! it with [`open_manifest`].
//!
//! Built directly on RustCrypto (`aes-siv`, `aes-gcm-siv`, `hkdf`). Only
//! authenticated AEADs are ever compiled in, so an unauthenticated mandate
//! is structurally unrepresentable (spec §9.2).
//!
//! The normative format is the obsigil specification; section references in
//! this source (e.g. `spec §5.2`) point there.
//!
//! # Example
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use obsigil::{open_manifest, Issuer, Mandate, MandateKey, Manifest, Verifier};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Access { role: String }
//! #[derive(Serialize, Deserialize)]
//! struct Ui { theme: String }
//!
//! // One 64-byte secret, provisioned to both sides (use
//! // `MandateKey::generate()` in production).
//! let issuer_key = MandateKey::from_bytes([42u8; 64])?;
//!
//! // Issuer: an authoritative mandate plus an advisory public manifest.
//! let token = Issuer::new(issuer_key)
//!     .mandate(&Access { role: "admin".into() })
//!     .exp(4_000_000_000)
//!     .audience(["api"])
//!     .manifest("auth.example", &Ui { theme: "dark".into() })
//!     .mint()?;
//!
//! // Front end: read the manifest with no secret (advisory only).
//! let manifest: Manifest<Ui> = open_manifest(&token).expect("present");
//! assert_eq!(manifest.issuer(), "auth.example");
//!
//! // Backend: verify the mandate (authoritative). `now` is pinned here
//! // for a deterministic example; omit it to read the system clock.
//! let verify_key = MandateKey::from_bytes([42u8; 64])?;
//! let mandate: Mandate<Access> = Verifier::new()
//!     .key(&verify_key)
//!     .audience("api")
//!     .now(1_000_000_000)
//!     .verify(&token)?;
//! assert_eq!(mandate.app().role, "admin");
//! # Ok(()) }
//! ```

// At least one serialization format must be compiled in; without one the
// mint/verify API cannot encode or decode claims (spec §7).
#[cfg(not(any(feature = "json", feature = "toml", feature = "cbor")))]
compile_error!(
    "obsigil requires at least one serialization feature: \
     `json` (the default), `toml`, or `cbor`"
);

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
pub use key::MandateKey;
pub use mint::{Issuer, MintBuilder};
pub use reserved::{Mandate, Manifest, NoApp};
pub use types::{tid_issued_at, Alg, Encoding, Format, NumericDate, MANIFEST_KEY};
pub use verify::{open_manifest, Verifier};

// Re-exported for callers handling `tid` (spec §11.3).
pub use uuid::Uuid;
