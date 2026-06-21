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
use crate::serial;
use crate::token::parse;
use crate::types::{Alg, NumericDate, MANIFEST_KEY};

/// Lowest legal decoded half length: the 16-byte AEAD floor plus at least one
/// byte of CBOR plaintext (the shortest being the empty map, `0xa0`) (§5.2).
const MIN_HALF_BYTES: usize = 17;

/// Hard ceiling on clock-skew leeway, in seconds (spec §9.9): a configured
/// leeway is bounded by this maximum so an over-large value cannot silently
/// extend a token past its `exp`. The spec's example bound is 60 seconds.
const MAX_LEEWAY: NumericDate = 60;

/// Default cap on a half's decoded byte length (spec §9.9): a generous bound
/// that admits any realistic mandate while refusing an attacker-supplied
/// oversize half before any trial decryption. Override with
/// [`Verifier::max_decoded_len`].
const DEFAULT_MAX_DECODED_LEN: usize = 64 * 1024;

/// A configured mandate verifier (spec §9). Verify against one or more
/// candidate keys by trial decryption (spec §9.4); reusable across tokens.
pub struct Verifier<'a> {
    keys: Vec<&'a MandateKey>,
    audience: Option<String>,
    leeway: NumericDate,
    now: Option<NumericDate>,
    max_decoded_len: usize,
}

impl Default for Verifier<'_> {
    fn default() -> Self {
        Verifier {
            keys: Vec::new(),
            audience: None,
            leeway: 0,
            now: None,
            max_decoded_len: DEFAULT_MAX_DECODED_LEN,
        }
    }
}

impl<'a> Verifier<'a> {
    /// A new verifier with no keys, no audience, no leeway, and the default
    /// maximum decoded half size (64 KiB).
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

    /// Allow a clock-skew leeway when checking `exp` (spec §12.1). The leeway
    /// is bounded by a hard maximum of 60 seconds (spec §9.9): a larger value
    /// is clamped down, so an over-large leeway can never silently extend a
    /// token past its expiry.
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway.as_secs().min(MAX_LEEWAY as u64) as NumericDate;
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

    /// Set the maximum decoded byte length accepted for the mandate half
    /// (spec §9.9). A half whose decoded ciphertext exceeds this is rejected
    /// uniformly, before any trial decryption, so the bound caps per-key AEAD
    /// work on attacker input without becoming an oracle. Defaults to 64 KiB.
    pub fn max_decoded_len(mut self, max: usize) -> Self {
        self.max_decoded_len = max;
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

        // §9.9: bound the half before any decode or trial decryption so an
        // oversize token cannot force repeated per-key AEAD work. Guard the
        // encoded length first (a cheap over-estimate of the decoded length —
        // hex is the densest at 2 chars/byte), then the decoded length exactly.
        if half.text.len() > self.max_decoded_len.saturating_mul(2).saturating_add(8) {
            return Err(Reason::Malformed);
        }
        let sealed = decode(half.text, parsed.encoding).ok_or(Reason::Malformed)?;
        if sealed.len() < MIN_HALF_BYTES || sealed.len() > self.max_decoded_len {
            return Err(Reason::Malformed);
        }

        // Trial decryption over candidate keys; wrong key fails closed. The
        // decrypted plaintext carries the mandate's secret clauses, so it is
        // wiped on drop (the sealed ciphertext is public and needs no wipe).
        let plain = self
            .keys
            .iter()
            .find_map(|k| open(&sealed, k.bytes(), alg))
            .map(zeroize::Zeroizing::new)
            .ok_or(Reason::AuthFailed)?;

        let clauses: Clauses<T> = serial::from_mandate_plaintext(&plain)?;

        // tid present and a well-formed UUIDv7: version field 7 AND the RFC
        // 4122 variant 0b10 (spec §12.3). Checking the version alone would
        // accept a v7-versioned UUID carrying a non-conformant variant.
        let tid = clauses.tid.ok_or(Reason::BadTid)?;
        if tid.get_version_num() != 7 || tid.get_variant() != uuid::Variant::RFC4122 {
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
/// an unsupported algorithm, non-canonical CBOR, or a manifest missing its
/// `iss`. Never an oracle.
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
    // Bound the half (§9.9) before decode/decrypt, matching the verifier's
    // default cap. The manifest is keyless (one decryption, no trial loop), so
    // there is no per-key amplification, but a ceiling still bounds the work.
    if half.text.len() > DEFAULT_MAX_DECODED_LEN.saturating_mul(2).saturating_add(8) {
        return None;
    }
    let sealed = decode(half.text, parsed.encoding)?;
    if sealed.len() < MIN_HALF_BYTES || sealed.len() > DEFAULT_MAX_DECODED_LEN {
        return None;
    }
    let plain = open(&sealed, &MANIFEST_KEY, alg)?;
    let claims: Claims<T> = serial::from_manifest_plaintext(&plain)?;
    Some(Manifest { inner: claims })
}
