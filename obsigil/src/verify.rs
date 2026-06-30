//! Verifying — the authoritative backend side (the Audiences section, §9; the Security Considerations, §16; the Reserved fields section, §8). All
//! rejections collapse to a single opaque [`Error`]; the granular cause is
//! available via [`Error::reason`] for internal logging only (the uniform-failure rule of the Security Considerations, §16.6).
//!
//! The keyless reads at the foot of this module ([`claims`], [`manifest`],
//! [`mandate`], [`manifest_plaintext`], [`authorization_header`]) need no
//! secret: they slice or open the public manifest, or carve out a standalone
//! half a front end can forward.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::de::DeserializeOwned;

use crate::aead::open;
use crate::encoding::decode;
use crate::error::{Error, Reason};
use crate::key::MandateKey;
use crate::reserved::{Claims, Clauses, MandateFields, ManifestFields};
use crate::serial;
use crate::token::parse;
use crate::types::{Alg, NumericDate, MANIFEST_KEY};

/// Lowest legal decoded half length: the 16-byte AEAD floor plus at least one
/// byte of CBOR plaintext (the shortest being the empty map, `0xa0`) (the Sealing parameters and output layout, §6.2).
const MIN_HALF_BYTES: usize = 17;

/// Hard ceiling on clock-skew leeway, in seconds (the Limits and robustness rules of the Security Considerations, §16.10): a configured
/// leeway is bounded by this maximum so an over-large value cannot silently
/// extend a token past its `exp`. The spec's example bound is 60 seconds.
const MAX_LEEWAY: NumericDate = 60;

/// Default cap on a half's decoded byte length (the Limits and robustness rules of the Security Considerations, §16.10): a generous bound
/// that admits any realistic mandate while refusing an attacker-supplied
/// oversize half before any trial decryption. Override with
/// [`Verifier::max_decoded_len`].
const DEFAULT_MAX_DECODED_LEN: usize = 64 * 1024;

/// A configured mandate verifier (the Verification configuration, §12.5). Verify against one or more
/// candidate keys by trial decryption (the trial-decryption key selection of the Security Considerations, §16.5); reusable across tokens.
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

    /// Add a candidate mandate key (trial decryption, the key-selection rule of the Security Considerations, §16.5).
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
    ///     .clauses(&NoApp::default())
    ///     .exp(4_000_000_000)
    ///     .mint()?;
    ///
    /// // Trial decryption: each candidate is tried; the wrong key fails
    /// // closed, the right one authenticates (the trial-decryption key selection of the Security Considerations, §16.5).
    /// let wrong = MandateKey::from_bytes([1u8; 64])?;
    /// let right = MandateKey::from_bytes([42u8; 64])?;
    /// assert!(Verifier::new()
    ///     .keys([&wrong, &right])
    ///     .now(1_000_000_000)
    ///     .clauses::<NoApp>(&token)
    ///     .is_ok());
    /// # Ok(()) }
    /// ```
    pub fn keys<I: IntoIterator<Item = &'a MandateKey>>(mut self, keys: I) -> Self {
        self.keys.extend(keys);
        self
    }

    /// Set this verifier's identifier, checked for membership in a present
    /// `aud` clause (the `aud` field, §8.4).
    pub fn audience(mut self, id: impl Into<String>) -> Self {
        self.audience = Some(id.into());
        self
    }

    /// Allow a clock-skew leeway when checking `exp` (the Verification configuration, §12.5). The leeway
    /// is bounded by a hard maximum of 60 seconds (the Limits and robustness rules of the Security Considerations, §16.10): a larger value
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
    ///     .clauses(&NoApp::default())
    ///     .exp(1_000)
    ///     .mint()?;
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    ///
    /// // Before exp: accepted. At/after exp: rejected, unless leeway covers it.
    /// assert!(Verifier::new().key(&key).now(500).clauses::<NoApp>(&token).is_ok());
    /// assert!(Verifier::new().key(&key).now(1_050).clauses::<NoApp>(&token).is_err());
    /// assert!(Verifier::new().key(&key).now(1_050).leeway(Duration::from_secs(100))
    ///     .clauses::<NoApp>(&token).is_ok());
    /// # Ok(()) }
    /// ```
    pub fn now(mut self, now: NumericDate) -> Self {
        self.now = Some(now);
        self
    }

    /// Set the maximum decoded byte length accepted for the mandate half
    /// (the Limits and robustness rules of the Security Considerations, §16.10). A half whose decoded ciphertext exceeds this is rejected
    /// uniformly, before any trial decryption, so the bound caps per-key AEAD
    /// work on attacker input without becoming an oracle. Defaults to 64 KiB.
    pub fn max_decoded_len(mut self, max: usize) -> Self {
        self.max_decoded_len = max;
        self
    }

    /// Verify a token's mandate and return its clauses (the Audiences section, §9; the Security Considerations, §16; the Reserved fields section, §8).
    /// Accepts a full token or the forwarded `.0mandate` form; the manifest
    /// is never parsed or trusted. On any failure returns one opaque
    /// [`Error`] (the uniform-failure rule of the Security Considerations, §16.6).
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use obsigil::{Clauses, Issuer, MandateKey, Verifier};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct Access { role: String }
    ///
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .clauses(&Access { role: "admin".into() })
    ///     .exp(4_000_000_000)
    ///     .mint()?;
    ///
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    /// let clauses: Clauses<Access> = Verifier::new()
    ///     .key(&key)
    ///     .now(1_000_000_000)
    ///     .clauses(&token)?;
    /// assert_eq!(clauses.app().role, "admin");
    /// # Ok(()) }
    /// ```
    pub fn clauses<T: DeserializeOwned>(&self, token: &str) -> Result<Clauses<T>, Error> {
        self.clauses_inner(token).map_err(Error::new)
    }

    /// Authenticate and canonically decode a token's mandate, returning its
    /// clauses **without** the policy value-checks (the authentication-vs-policy layering of the Security Considerations, §16.3). The
    /// half is still authenticated under a candidate key and rejected if its
    /// plaintext is not canonical CBOR — only the value policy is skipped:
    /// `tid` well-formedness (UUIDv7 version/variant), `exp` expiry, and `aud`
    /// membership. Use for introspecting a token whose validity is to be
    /// judged separately; prefer [`clauses`](Self::clauses) for enforcement.
    ///
    /// The reserved fields' presence and CBOR types are still required, so the
    /// returned [`Clauses`] accessors stay total.
    pub fn clauses_unchecked<T: DeserializeOwned>(&self, token: &str) -> Result<Clauses<T>, Error> {
        self.clauses_unchecked_inner(token).map_err(Error::new)
    }

    /// Authenticate a token's mandate and return its raw decrypted CBOR
    /// octets, with no parsing (the authentication-vs-policy layering of the Security Considerations, §16.3). The half is decoded and trial-
    /// decrypted exactly as in [`clauses`](Self::clauses), but the plaintext
    /// is returned verbatim — neither canonical-CBOR-checked nor split into
    /// fields. The octets are a half's secret clauses; the caller owns and
    /// is responsible for handling (e.g. zeroizing) them.
    pub fn mandate_plaintext(&self, token: &str) -> Result<Vec<u8>, Error> {
        self.authenticate(token).map_err(Error::new)
    }

    /// Decode and trial-decrypt a token's mandate half to its raw plaintext
    /// octets (the trial-decryption key selection, §16.5; the Limits and robustness rules of the Security Considerations, §16.10), without canonical-CBOR validation. Shared by
    /// every verifier terminal.
    fn authenticate(&self, token: &str) -> Result<Vec<u8>, Reason> {
        let parsed = parse(token).map_err(|_| Reason::Malformed)?;
        let half = parsed.mandate.ok_or(Reason::EmptyMandate)?;
        let alg = Alg::from_code(half.alg_code).ok_or(Reason::Unsupported)?;

        // Limits and robustness (§16.10): bound the half before any decode or trial decryption so an
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

        // Trial decryption over candidate keys; wrong key fails closed.
        self.keys
            .iter()
            .find_map(|k| open(&sealed, k.bytes(), alg))
            .ok_or(Reason::AuthFailed)
    }

    /// Authenticate, then strictly decode the canonical-CBOR plaintext into
    /// its reserved fields and application value. The plaintext carries the
    /// mandate's secret clauses, so it is wiped on drop (the sealed ciphertext
    /// is public and needs no wipe).
    fn authenticate_and_decode<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<MandateFields<T>, Reason> {
        let plain = zeroize::Zeroizing::new(self.authenticate(token)?);
        serial::from_mandate_plaintext(&plain)
    }

    fn clauses_inner<T: DeserializeOwned>(&self, token: &str) -> Result<Clauses<T>, Reason> {
        let fields = self.authenticate_and_decode::<T>(token)?;

        // tid present and a well-formed UUIDv7: version field 7 AND the RFC
        // 4122 variant 0b10 (the `tid` field, §8.2). Checking the version alone would
        // accept a v7-versioned UUID carrying a non-conformant variant.
        let tid = fields.tid.ok_or(Reason::BadTid)?;
        if tid.get_version_num() != 7 || tid.get_variant() != uuid::Variant::RFC4122 {
            return Err(Reason::BadTid);
        }

        // exp present and not at/past now (with leeway) (the `exp` field, §8.3).
        let exp = fields.exp.ok_or(Reason::MissingClause)?;
        let now = self.now.unwrap_or_else(now_unix);
        if now >= exp.saturating_add(self.leeway) {
            return Err(Reason::Expired);
        }

        // aud membership, if present (the `aud` field, §8.4).
        if let Some(aud) = &fields.aud {
            if aud.is_empty() {
                return Err(Reason::AudienceMismatch);
            }
            let me = self.audience.as_deref().ok_or(Reason::AudienceMismatch)?;
            if !aud_contains(aud, me) {
                return Err(Reason::AudienceMismatch);
            }
        }

        Ok(Clauses { inner: fields })
    }

    fn clauses_unchecked_inner<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<Clauses<T>, Reason> {
        let fields = self.authenticate_and_decode::<T>(token)?;
        // Structural presence is required so the accessors are total, but the
        // value policy — tid version/variant, exp expiry, aud membership — is
        // deliberately skipped here.
        fields.tid.ok_or(Reason::BadTid)?;
        fields.exp.ok_or(Reason::MissingClause)?;
        Ok(Clauses { inner: fields })
    }
}

/// Constant-time membership test for `aud` (the uniform-failure rule of the Security Considerations, §16.6: don't leak which
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

/// Read the manifest of a token for display (the published manifest key, §5.2; the `iss` field, §8.6). Keyless and
/// advisory — never authoritative (the non-authoritative-manifest rule of the Security Considerations, §16.7). Returns `None` on anything
/// untrustworthy: no manifest, malformed token, bad encoding, auth failure,
/// an unsupported algorithm, non-canonical CBOR, or a manifest missing its
/// `iss`. Never an oracle.
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{claims, Issuer, MandateKey, NoApp};
/// // A mandate-only token has no manifest half, so this returns `None`.
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .clauses(&NoApp::default())
///     .exp(4_000_000_000)
///     .mint()?;
/// assert!(claims::<NoApp>(&token).is_none());
/// # Ok(()) }
/// ```
pub fn claims<T: DeserializeOwned>(token: &str) -> Option<Claims<T>> {
    let plain = manifest_plaintext(token)?;
    let fields: ManifestFields<T> = serial::from_manifest_plaintext(&plain)?;
    Some(Claims { inner: fields })
}

/// Return the token's manifest half as a standalone, well-formed
/// manifest-only token — the trailing-separator `manifest0.` form (the Token structure section, §4).
/// `None` if the token has no manifest half or is malformed. Keyless and
/// purely structural: the ciphertext is sliced out, not decrypted.
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{manifest, Issuer, MandateKey, NoApp};
/// use serde::{Deserialize, Serialize};
/// #[derive(Serialize, Deserialize)]
/// struct Ui { theme: String }
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .clauses(&NoApp::default())
///     .exp(4_000_000_000)
///     .manifest("auth.example", &Ui { theme: "dark".into() })
///     .mint()?;
/// let half = manifest(&token).expect("has a manifest half");
/// assert!(half.ends_with('.')); // trailing-separator manifest-only token
/// # Ok(()) }
/// ```
pub fn manifest(token: &str) -> Option<String> {
    let parsed = parse(token).ok()?;
    let half = parsed.manifest?;
    let mut out = String::with_capacity(half.text.len() + 1 + parsed.separator.len_utf8());
    out.push_str(half.text);
    out.push(half.alg_code);
    out.push(parsed.separator);
    Some(out)
}

/// Return the token's mandate half as a standalone, well-formed mandate-only
/// token — the leading-separator `.0mandate` form (the Audiences section, §9). This is the
/// value a front end forwards to the backend. `None` if the token has no
/// mandate half or is malformed. Keyless and purely structural.
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{mandate, Issuer, MandateKey, NoApp, Verifier};
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .clauses(&NoApp::default())
///     .exp(4_000_000_000)
///     .mint()?;
/// let forwarded = mandate(&token).expect("has a mandate half");
/// // The carved-out half still verifies on its own.
/// let key = MandateKey::from_bytes([42u8; 64])?;
/// assert!(Verifier::new().key(&key).now(1_000_000_000)
///     .clauses::<NoApp>(&forwarded).is_ok());
/// # Ok(()) }
/// ```
pub fn mandate(token: &str) -> Option<String> {
    let parsed = parse(token).ok()?;
    parsed.mandate.as_ref()?;
    let mut out = String::with_capacity(parsed.separator.len_utf8() + parsed.mandate_part.len());
    out.push(parsed.separator);
    out.push_str(parsed.mandate_part);
    Some(out)
}

/// Keyless decrypt of the token's manifest half under the public
/// [`MANIFEST_KEY`], returning its raw CBOR octets with no parsing
/// (the published manifest key, §5.2). `None` on no manifest half, a malformed token, bad encoding,
/// an unsupported algorithm, or tamper/auth failure. Advisory only.
pub fn manifest_plaintext(token: &str) -> Option<Vec<u8>> {
    let parsed = parse(token).ok()?;
    let half = parsed.manifest?;
    let alg = Alg::from_code(half.alg_code)?;
    // Bound the half (the Limits and robustness rules, §16.10) before decode/decrypt, matching the verifier's
    // default cap. The manifest is keyless (one decryption, no trial loop), so
    // there is no per-key amplification, but a ceiling still bounds the work.
    if half.text.len() > DEFAULT_MAX_DECODED_LEN.saturating_mul(2).saturating_add(8) {
        return None;
    }
    let sealed = decode(half.text, parsed.encoding)?;
    if sealed.len() < MIN_HALF_BYTES || sealed.len() > DEFAULT_MAX_DECODED_LEN {
        return None;
    }
    open(&sealed, &MANIFEST_KEY, alg)
}

/// Wrap a token's forwardable mandate half as an HTTP `Authorization` value
/// of the form `"<scheme> <mandate>"` (the Audiences section, §9). `None` if the token has no
/// mandate half or is malformed. A thin convenience over [`mandate`].
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{authorization_header, Issuer, MandateKey, NoApp};
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .clauses(&NoApp::default())
///     .exp(4_000_000_000)
///     .mint()?;
/// let header = authorization_header(&token, "Bearer").expect("has a mandate");
/// assert!(header.starts_with("Bearer ."));
/// # Ok(()) }
/// ```
pub fn authorization_header(token: &str, scheme: &str) -> Option<String> {
    let half = mandate(token)?;
    let mut out = String::with_capacity(scheme.len() + 1 + half.len());
    out.push_str(scheme);
    out.push(' ');
    out.push_str(&half);
    Some(out)
}
