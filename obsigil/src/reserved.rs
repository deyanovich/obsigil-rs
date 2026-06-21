//! Reserved fields and the verified/opened views (spec §11). The library
//! owns the reserved fields, carried at negative integer keys (spec §7);
//! application data is an arbitrary `T` merged in at non-negative integer and
//! text-string keys. There is no `iat` — issue time derives from `tid`
//! (spec §11.3).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{tid_issued_at, NumericDate};

/// Use as the app-data type `T` when a half carries only reserved fields.
/// Serializes as an empty map; ignores any extra fields on the way in.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoApp {}

/// A mandate's reserved clauses plus the application value, read from (or
/// assembled for) the canonical-CBOR map (spec §7, §11). `exp`/`tid` are
/// `Option` so the verifier can report a missing one as a precise reason; a
/// verified mandate always carries both.
#[derive(Debug)]
pub(crate) struct Clauses<T> {
    pub exp: Option<NumericDate>,
    pub tid: Option<Uuid>,
    pub iss: Option<String>,
    pub aud: Option<Vec<String>>,
    pub sub: Option<String>,
    pub app: T,
}

/// A verified mandate. Constructible only by [`Verifier::verify`], so its
/// existence is proof the mandate authenticated and passed policy
/// (spec §9.2, §11).
///
/// [`Verifier::verify`]: crate::Verifier::verify
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{Issuer, MandateKey, NoApp, Verifier};
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .mandate(&NoApp::default())
///     .exp(4_000_000_000)
///     .subject("user-1")
///     .mint()?;
/// let key = MandateKey::from_bytes([42u8; 64])?;
/// let mandate = Verifier::new().key(&key).now(1_000_000_000)
///     .verify::<NoApp>(&token)?;
/// assert_eq!(mandate.exp(), 4_000_000_000);
/// assert_eq!(mandate.subject(), Some("user-1"));
/// assert_eq!(mandate.tid().get_version_num(), 7); // UUIDv7 (spec §11.3)
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct Mandate<T> {
    pub(crate) inner: Clauses<T>,
}

impl<T> Mandate<T> {
    /// Authoritative expiry (spec §11.1).
    pub fn exp(&self) -> NumericDate {
        self.inner.exp.expect("verified mandate has exp")
    }

    /// The unique token id (UUIDv7, spec §11.3).
    pub fn tid(&self) -> Uuid {
        self.inner.tid.expect("verified mandate has tid")
    }

    /// Issue time, derived from `tid` (spec §11.3).
    pub fn issued_at(&self) -> NumericDate {
        tid_issued_at(self.tid())
    }

    /// Issuer, for audit (spec §11.2).
    pub fn issuer(&self) -> Option<&str> {
        self.inner.iss.as_deref()
    }

    /// Intended verifiers (spec §11.4).
    pub fn audience(&self) -> Option<&[String]> {
        self.inner.aud.as_deref()
    }

    /// Subject authorized (spec §11.5).
    pub fn subject(&self) -> Option<&str> {
        self.inner.sub.as_deref()
    }

    /// The application clauses.
    pub fn app(&self) -> &T {
        &self.inner.app
    }

    /// Consume the mandate, yielding the application clauses.
    pub fn into_app(self) -> T {
        self.inner.app
    }
}

/// A manifest's reserved claims plus the application value (spec §7, §11).
/// `iss` is required: a manifest lacking it is malformed and yields nothing
/// (spec §11.2). `exp`, if present, is an advisory refresh hint.
#[derive(Debug)]
pub(crate) struct Claims<T> {
    pub iss: String,
    pub exp: Option<NumericDate>,
    pub app: T,
}

/// An opened manifest. Advisory only — never authoritative (spec §9.6).
#[derive(Debug)]
pub struct Manifest<T> {
    pub(crate) inner: Claims<T>,
}

impl<T> Manifest<T> {
    /// Issuer, for display (spec §11.2).
    pub fn issuer(&self) -> &str {
        &self.inner.iss
    }

    /// Advisory refresh hint, if present (spec §11.1).
    pub fn exp(&self) -> Option<NumericDate> {
        self.inner.exp
    }

    /// The application claims.
    pub fn app(&self) -> &T {
        &self.inner.app
    }

    /// Consume the manifest, yielding the application claims.
    pub fn into_app(self) -> T {
        self.inner.app
    }
}
