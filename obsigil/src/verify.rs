//! Verifying — the authoritative backend side (spec §8, §9, §11). All
//! rejections collapse to a single opaque [`Error`]; the granular cause is
//! available via [`Error::reason`] for internal logging only (spec §9.5).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;

use crate::aead::open;
use crate::encoding::decode;
use crate::error::{Error, Reason};
use crate::key::MandateKey;
use crate::reserved::{Claims, Clauses, Mandate, Manifest};
use crate::serial::from_fields;
use crate::token::parse;
use crate::types::{Alg, NumericDate, MANIFEST_KEY};

/// Lowest legal decoded half length: 16-byte AEAD floor + 1-byte tag (§5.2).
const MIN_HALF_BYTES: usize = 17;

/// A configured mandate verifier (spec §9). Verify against one or more
/// candidate keys by trial decryption (spec §9.4); reusable across tokens.
#[derive(Default)]
pub struct Verifier<'a> {
    keys: Vec<&'a MandateKey>,
    audience: Option<String>,
    leeway: NumericDate,
    now: Option<NumericDate>,
}

impl<'a> Verifier<'a> {
    /// A new verifier with no keys, no audience, and no leeway.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate mandate key (trial decryption, spec §9.4).
    pub fn key(mut self, key: &'a MandateKey) -> Self {
        self.keys.push(key);
        self
    }

    /// Add several candidate mandate keys.
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use obsigil::{Issuer, MandateKey, NoApp, Verifier};
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .mandate(&NoApp::default())
    ///     .exp(4_000_000_000)
    ///     .mint()?;
    ///
    /// // Trial decryption: each candidate is tried; the wrong key fails
    /// // closed, the right one authenticates (spec §9.4).
    /// let wrong = MandateKey::from_bytes([1u8; 64])?;
    /// let right = MandateKey::from_bytes([42u8; 64])?;
    /// assert!(Verifier::new()
    ///     .keys([&wrong, &right])
    ///     .now(1_000_000_000)
    ///     .verify::<NoApp>(&token)
    ///     .is_ok());
    /// # Ok(()) }
    /// ```
    pub fn keys<I: IntoIterator<Item = &'a MandateKey>>(mut self, keys: I) -> Self {
        self.keys.extend(keys);
        self
    }

    /// Set this verifier's identifier, checked for membership in a present
    /// `aud` clause (spec §11.4).
    pub fn audience(mut self, id: impl Into<String>) -> Self {
        self.audience = Some(id.into());
        self
    }

    /// Allow a clock-skew leeway when checking `exp` (spec §11.1).
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway.as_secs() as NumericDate;
        self
    }

    /// Pin "now" (seconds since epoch) instead of reading the system clock —
    /// for testing and reproducibility.
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::time::Duration;
    /// use obsigil::{Issuer, MandateKey, NoApp, Verifier};
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .mandate(&NoApp::default())
    ///     .exp(1_000)
    ///     .mint()?;
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    ///
    /// // Before exp: accepted. At/after exp: rejected, unless leeway covers it.
    /// assert!(Verifier::new().key(&key).now(500).verify::<NoApp>(&token).is_ok());
    /// assert!(Verifier::new().key(&key).now(1_050).verify::<NoApp>(&token).is_err());
    /// assert!(Verifier::new().key(&key).now(1_050).leeway(Duration::from_secs(100))
    ///     .verify::<NoApp>(&token).is_ok());
    /// # Ok(()) }
    /// ```
    pub fn now(mut self, now: NumericDate) -> Self {
        self.now = Some(now);
        self
    }

    /// Verify a token's mandate and return its clauses (spec §8, §9, §11).
    /// Accepts a full token or the forwarded `.0mandate` form; the manifest
    /// is never parsed or trusted. On any failure returns one opaque
    /// [`Error`] (spec §9.5).
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use obsigil::{Issuer, Mandate, MandateKey, Verifier};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct Access { role: String }
    ///
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .mandate(&Access { role: "admin".into() })
    ///     .exp(4_000_000_000)
    ///     .mint()?;
    ///
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    /// let mandate: Mandate<Access> = Verifier::new()
    ///     .key(&key)
    ///     .now(1_000_000_000)
    ///     .verify(&token)?;
    /// assert_eq!(mandate.app().role, "admin");
    /// # Ok(()) }
    /// ```
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<Mandate<T>, Error> {
        self.verify_inner(token).map_err(Error::new)
    }

    fn verify_inner<T: DeserializeOwned>(&self, token: &str) -> Result<Mandate<T>, Reason> {
        let parsed = parse(token).map_err(|_| Reason::Malformed)?;
        let half = parsed.mandate.ok_or(Reason::EmptyMandate)?;
        let alg = Alg::from_code(half.alg_code).ok_or(Reason::Unsupported)?;

        let sealed = decode(half.text, parsed.encoding).ok_or(Reason::Malformed)?;
        if sealed.len() < MIN_HALF_BYTES {
            return Err(Reason::Malformed);
        }

        // Trial decryption over candidate keys; wrong key fails closed.
        let plain = self
            .keys
            .iter()
            .find_map(|k| open(&sealed, k.bytes(), alg))
            .ok_or(Reason::AuthFailed)?;

        let (tag, fields) = plain.split_first().ok_or(Reason::Malformed)?;
        let clauses: Clauses<T> = from_fields(*tag, fields).ok_or(Reason::Malformed)?;

        // tid present and a well-formed UUIDv7 (spec §11.3).
        let tid = clauses.tid.ok_or(Reason::BadTid)?;
        if tid.get_version_num() != 7 {
            return Err(Reason::BadTid);
        }

        // exp present and not at/past now (with leeway) (spec §11.1).
        let exp = clauses.exp.ok_or(Reason::MissingClause)?;
        let now = self.now.unwrap_or_else(now_unix);
        if now >= exp.saturating_add(self.leeway) {
            return Err(Reason::Expired);
        }

        // aud membership, if present (spec §11.4).
        if let Some(aud) = &clauses.aud {
            if aud.is_empty() {
                return Err(Reason::AudienceMismatch);
            }
            let me = self.audience.as_deref().ok_or(Reason::AudienceMismatch)?;
            if !aud_contains(aud, me) {
                return Err(Reason::AudienceMismatch);
            }
        }

        Ok(Mandate { inner: clauses })
    }
}

/// Constant-time membership test for `aud` (spec §9.5: don't leak which
/// check failed). No early exit on a match.
fn aud_contains(aud: &[String], me: &str) -> bool {
    use subtle::ConstantTimeEq;
    let mut hit = false;
    for a in aud {
        hit |= bool::from(a.as_bytes().ct_eq(me.as_bytes()));
    }
    hit
}

fn now_unix() -> NumericDate {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as NumericDate)
        .unwrap_or(0)
}

/// Open the manifest of a token for display (spec §4.2, §11.2). Keyless and
/// advisory — never authoritative (spec §9.6). Returns `None` on anything
/// untrustworthy: no manifest, malformed token, bad encoding, auth failure,
/// unsupported algorithm/serialization, or a manifest missing its `iss`.
/// Never an oracle.
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{open_manifest, Issuer, MandateKey, NoApp};
/// // A mandate-only token has no manifest half, so this returns `None`.
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .mandate(&NoApp::default())
///     .exp(4_000_000_000)
///     .mint()?;
/// assert!(open_manifest::<NoApp>(&token).is_none());
/// # Ok(()) }
/// ```
pub fn open_manifest<T: DeserializeOwned>(token: &str) -> Option<Manifest<T>> {
    let parsed = parse(token).ok()?;
    let half = parsed.manifest?;
    let alg = Alg::from_code(half.alg_code)?;
    let sealed = decode(half.text, parsed.encoding)?;
    if sealed.len() < MIN_HALF_BYTES {
        return None;
    }
    let plain = open(&sealed, &MANIFEST_KEY, alg)?;
    let (tag, fields) = plain.split_first()?;
    let claims: Claims<T> = from_fields(*tag, fields)?;
    Some(Manifest { inner: claims })
}
