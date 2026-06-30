//! Reserved fields and the verified/opened views (the Reserved fields section, §8). The library
//! owns the reserved fields, carried at negative integer keys (the Serialization rules, §7);
//! application data is an arbitrary `T` merged in at non-negative integer and
//! text-string keys. There is no `iat` — issue time derives from `tid`
//! (the `tid` field, §8.2).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{tid_issued_at, NumericDate};

/// Use as the app-data type `T` when a half carries only reserved fields.
/// Serializes as an empty map; ignores any extra fields on the way in.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoApp {}

/// A mandate's reserved clauses plus the application value, read from (or
/// assembled for) the canonical-CBOR map (the Serialization rules, §7; the Reserved fields section, §8). `exp`/`tid` are
/// `Option` so the verifier can report a missing one as a precise reason; a
/// verified mandate always carries both. Internal backing for [`Clauses`].
#[derive(Debug)]
pub(crate) struct MandateFields<T> {
    pub exp: Option<NumericDate>,
    pub tid: Option<Uuid>,
    pub iss: Option<String>,
    pub aud: Option<Vec<String>>,
    pub sub: Option<String>,
    pub app: T,
}

/// A verified mandate's clauses. Constructible only by the verifier
/// terminals, so its existence is proof the mandate authenticated and
/// decoded as canonical CBOR (the mandate-must-be-authenticated rule of the Security Considerations, §16.2; the Reserved fields section, §8).
///
/// [`Verifier::clauses`]: crate::Verifier::clauses
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{Issuer, MandateKey, NoApp, Verifier};
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .clauses(&NoApp::default())
///     .exp(4_000_000_000)
///     .subject("user-1")
///     .mint()?;
/// let key = MandateKey::from_bytes([42u8; 64])?;
/// let clauses = Verifier::new().key(&key).now(1_000_000_000)
///     .clauses::<NoApp>(&token)?;
/// assert_eq!(clauses.exp(), 4_000_000_000);
/// assert_eq!(clauses.subject(), Some("user-1"));
/// assert_eq!(clauses.tid().get_version_num(), 7); // UUIDv7 (the `tid` field, §8.2)
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct Clauses<T> {
    pub(crate) inner: MandateFields<T>,
}

impl<T> Clauses<T> {
    /// Authoritative expiry (the `exp` field, §8.3).
    pub fn exp(&self) -> NumericDate {
        self.inner.exp.expect("verified mandate has exp")
    }

    /// The unique token id (UUIDv7, the `tid` field, §8.2).
    pub fn tid(&self) -> Uuid {
        self.inner.tid.expect("verified mandate has tid")
    }

    /// Issue time, derived from `tid` (the `tid` field, §8.2).
    pub fn issued_at(&self) -> NumericDate {
        tid_issued_at(self.tid())
    }

    /// Issuer, for audit (the `iss` field, §8.6).
    pub fn issuer(&self) -> Option<&str> {
        self.inner.iss.as_deref()
    }

    /// Short alias for [`issuer`](Self::issuer).
    pub fn iss(&self) -> Option<&str> {
        self.issuer()
    }

    /// Intended verifiers (the `aud` field, §8.4).
    pub fn audience(&self) -> Option<&[String]> {
        self.inner.aud.as_deref()
    }

    /// Short alias for [`audience`](Self::audience).
    pub fn aud(&self) -> Option<&[String]> {
        self.audience()
    }

    /// Subject authorized (the `sub` field, §8.5).
    pub fn subject(&self) -> Option<&str> {
        self.inner.sub.as_deref()
    }

    /// Short alias for [`subject`](Self::subject).
    pub fn sub(&self) -> Option<&str> {
        self.subject()
    }

    /// The application clauses.
    pub fn app(&self) -> &T {
        &self.inner.app
    }

    /// Consume the clauses, yielding the application value.
    pub fn into_app(self) -> T {
        self.inner.app
    }
}

/// A manifest's reserved claims plus the application value (the Serialization rules, §7; the Reserved fields section, §8).
/// `iss` is required: a manifest lacking it is malformed and yields nothing
/// (the `iss` field, §8.6). `exp`, if present, is an advisory refresh hint. Internal
/// backing for [`Claims`].
#[derive(Debug)]
pub(crate) struct ManifestFields<T> {
    pub iss: String,
    pub exp: Option<NumericDate>,
    pub app: T,
}

/// An opened manifest's claims. Advisory only — never authoritative
/// (the non-authoritative-manifest rule of the Security Considerations, §16.7).
#[derive(Debug)]
pub struct Claims<T> {
    pub(crate) inner: ManifestFields<T>,
}

impl<T> Claims<T> {
    /// Issuer, for display (the `iss` field, §8.6).
    pub fn issuer(&self) -> &str {
        &self.inner.iss
    }

    /// Short alias for [`issuer`](Self::issuer).
    pub fn iss(&self) -> &str {
        self.issuer()
    }

    /// Advisory refresh hint, if present (the `exp` field, §8.3).
    pub fn exp(&self) -> Option<NumericDate> {
        self.inner.exp
    }

    /// The application claims.
    pub fn app(&self) -> &T {
        &self.inner.app
    }

    /// Consume the claims, yielding the application value.
    pub fn into_app(self) -> T {
        self.inner.app
    }
}
