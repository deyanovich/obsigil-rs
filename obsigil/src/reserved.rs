//! Reserved fields and the verified/opened views (spec §11). The library
//! owns the reserved names; application data is an arbitrary `T` merged via
//! `#[serde(flatten)]`. There is no `iat` — issue time derives from `tid`
//! (spec §11.3).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{tid_issued_at, NumericDate};

/// Use as the app-data type `T` when a half carries only reserved fields.
/// Serializes as an empty map; ignores any extra fields on the way in.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoApp {}

/// Mandate clauses on the wire (spec §11). `exp`/`tid` are `Option` so a
/// missing one deserializes to `None` and is reported as a precise reason
/// rather than a generic decode error; both are always present on mint.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Clauses<T> {
    #[serde(default)]
    pub exp: Option<NumericDate>,
    #[serde(default)]
    pub tid: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub: Option<String>,
    #[serde(flatten)]
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

/// Manifest claims on the wire (spec §11). `iss` is required: a manifest
/// lacking it is malformed and yields nothing (spec §11.2).
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct Claims<T> {
    pub iss: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exp: Option<NumericDate>,
    #[serde(flatten)]
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
