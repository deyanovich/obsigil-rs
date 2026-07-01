//! Error types. Verification failures are uniform and opaque to the bearer
//! (the uniform-failure rule of the Security Considerations, §16.6); minting and key errors are descriptive (the trusted side).

use core::fmt;

/// Why a verification was rejected. **Internal/diagnostic only.** Per
/// the uniform-failure rule of the Security Considerations (§16.6), a verifier MUST NOT signal *why* a token was rejected to the
/// bearer; this granular cause is for server-side logging and telemetry.
/// Never place it (or [`Error`]'s `Debug`) in a bearer-facing response.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Reason {
    /// Malformed token: bad separator count, degenerate half, bad encoding,
    /// truncated half, or undeserializable plaintext.
    Malformed,
    /// The algorithm code is not implemented by this build.
    Unsupported,
    /// AEAD authentication failed under every candidate key (wrong key,
    /// tampering, or wrong algorithm).
    AuthFailed,
    /// The mandate half is absent or empty.
    EmptyMandate,
    /// `tid` is absent or not a well-formed UUIDv7.
    BadTid,
    /// A required clause is missing (e.g. `exp`).
    MissingClause,
    /// The current time is at or past `exp` (allowing for leeway).
    Expired,
    /// `aud` is present and the verifier's identifier is not a member (or
    /// `aud` is an empty array).
    AudienceMismatch,
    /// The plaintext is not canonical CBOR — an indefinite-length item, a
    /// non-shortest integer, length, or float, a `NaN`, unsorted or duplicate
    /// map keys, or trailing bytes (the Serialization rules, §7; the Limits and robustness rules of the Security Considerations, §16.10).
    NonCanonical,
    /// A reserved field carries a value of the wrong CBOR type — e.g. `exp`
    /// not an integer, `aud` not an array of text strings (the Limits and robustness rules of the Security Considerations, §16.10).
    BadType,
    /// The half carries an unrecognized negative integer key. Negative keys
    /// are obsigil's namespace, so an unknown one fails closed (the Serialization rules, §7).
    UnknownReservedKey,
}

/// The single, opaque failure a verifier returns. Its [`Display`] is
/// uniform across every cause (the uniform-failure rule of the Security Considerations, §16.6); the granular [`Reason`] is
/// available via [`Error::reason`] for internal logging only.
///
/// [`Display`]: fmt::Display
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{Issuer, MandateKey, NoApp, Reason, Verifier};
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .clauses(&NoApp::default())
///     .exp(1_000)
///     .mint()?;
/// let key = MandateKey::from_bytes([42u8; 64])?;
/// let err = Verifier::new().key(&key).now(2_000)
///     .clauses::<NoApp>(&token)
///     .unwrap_err();
/// // The bearer sees one uniform message...
/// assert_eq!(err.to_string(), "obsigil: token rejected");
/// // ...while the server can log the precise internal cause.
/// assert!(matches!(err.reason(), Reason::Expired));
/// # Ok(()) }
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error(Reason);

impl Error {
    pub(crate) fn new(reason: Reason) -> Self {
        Error(reason)
    }

    /// The internal cause, for server-side logging/telemetry **only**. Do
    /// not surface this to the bearer (the uniform-failure rule of the Security Considerations, §16.6).
    pub fn reason(&self) -> Reason {
        self.0
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Uniform across all causes — never reveal `self.0`.
        f.write_str("obsigil: token rejected")
    }
}

// Detailed `Debug` carries the reason — intended for logs. It MUST NOT be
// echoed to the bearer (the same rule as `reason()`).
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Error").field(&self.0).finish()
    }
}

impl std::error::Error for Error {}

/// A rejected [`MandateKey`](crate::MandateKey) value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KeyError {
    /// The bytes equal the public manifest key — accepting it would let
    /// anyone mint valid mandates (the mandate construction, §5.1).
    IsManifestKey,
    /// The bytes are all zero.
    AllZero,
    /// A hex key string was not canonical lowercase hexadecimal (the Key
    /// format, §6.2): an uppercase digit, an odd length, or an out-of-alphabet
    /// character. A malformed key is a configuration error, kept distinct from
    /// the verifier's opaque failure — never folded into it.
    BadHexEncoding,
    /// A hex key string was canonical hexadecimal but did not decode to
    /// exactly 64 bytes (the Key format, §6.2).
    BadHexLength {
        /// The number of bytes the hex string decoded to.
        got: usize,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::IsManifestKey => {
                f.write_str("mandate key must not be the public manifest key")
            }
            KeyError::AllZero => f.write_str("mandate key must not be all zero"),
            KeyError::BadHexEncoding => {
                f.write_str("mandate key must be 128 lowercase hexadecimal digits")
            }
            KeyError::BadHexLength { got } => {
                write!(f, "mandate key must decode to 64 bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for KeyError {}

/// A failure while minting a token. Descriptive — minting is the trusted
/// side, so detail here is not an oracle.
#[derive(Debug)]
#[non_exhaustive]
pub enum MintError {
    /// A required field was not set (e.g. `exp`).
    Missing(&'static str),
    /// `aud` was set to an empty array (the `aud` field, §8.4).
    EmptyAudience,
    /// The provided `tid` is not a well-formed UUIDv7 — version 7 with the
    /// RFC 4122 variant (the `tid` field, §8.2). The auto-generated `tid` always is; this
    /// guards a `tid` set explicitly via [`MintBuilder::tid`](crate::MintBuilder::tid).
    BadTid,
    /// The chosen algorithm code is not compiled into this build.
    UnsupportedAlg(Alg),
    /// The application value did not serialize to a CBOR map. obsigil merges
    /// application fields into the half's map (the Serialization rules, §7), so the value must be
    /// a map/struct; use [`NoApp`](crate::NoApp) for a half with no app data.
    AppNotMap,
    /// An application field used a negative integer key, which is reserved to
    /// obsigil (the Serialization rules, §7). Application keys are non-negative integers and text
    /// strings.
    ReservedKey,
    /// An application field carried a floating-point `NaN`, which has no
    /// canonical CBOR encoding and is forbidden (the Serialization rules, §7).
    Nan,
    /// Serializing the fields failed.
    Serialization(String),
}

use crate::types::Alg;

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintError::Missing(field) => {
                write!(f, "obsigil mint: missing required field `{field}`")
            }
            MintError::EmptyAudience => {
                f.write_str("obsigil mint: `aud` must be a non-empty array")
            }
            MintError::BadTid => {
                f.write_str("obsigil mint: `tid` must be a UUIDv7 (version 7, RFC 4122 variant)")
            }
            MintError::UnsupportedAlg(a) => {
                write!(f, "obsigil mint: algorithm `{}` not enabled", a.code())
            }
            MintError::AppNotMap => {
                f.write_str("obsigil mint: application value must serialize to a CBOR map")
            }
            MintError::ReservedKey => {
                f.write_str("obsigil mint: application field used a reserved negative key")
            }
            MintError::Nan => f.write_str("obsigil mint: application field must not be NaN"),
            MintError::Serialization(msg) => write!(f, "obsigil mint: serialization failed: {msg}"),
        }
    }
}

impl std::error::Error for MintError {}
