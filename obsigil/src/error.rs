//! Error types. Verification failures are uniform and opaque to the bearer
//! (spec §9.5); minting and key errors are descriptive (the trusted side).

use core::fmt;

/// Why a verification was rejected. **Internal/diagnostic only.** Per spec
/// §9.5 a verifier MUST NOT signal *why* a token was rejected to the
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
}

/// The single, opaque failure a verifier returns. Its [`Display`] is
/// uniform across every cause (spec §9.5); the granular [`Reason`] is
/// available via [`Error::reason`] for internal logging only.
///
/// [`Display`]: fmt::Display
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use obsigil::{Issuer, MandateKey, NoApp, Reason, Verifier};
/// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
///     .mandate(&NoApp::default())
///     .exp(1_000)
///     .mint()?;
/// let key = MandateKey::from_bytes([42u8; 64])?;
/// let err = Verifier::new().key(&key).now(2_000)
///     .verify::<NoApp>(&token)
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
    /// not surface this to the bearer (spec §9.5).
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
    /// anyone mint valid mandates (spec §4.1).
    IsManifestKey,
    /// The bytes are all zero.
    AllZero,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::IsManifestKey => {
                f.write_str("mandate key must not be the public manifest key")
            }
            KeyError::AllZero => f.write_str("mandate key must not be all zero"),
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
    /// `aud` was set to an empty array (spec §11.4).
    EmptyAudience,
    /// The chosen algorithm code is not compiled into this build.
    UnsupportedAlg(Alg),
    /// The chosen serialization is not compiled into this build.
    UnsupportedFormat(Format),
    /// Serializing the fields failed.
    Serialization(String),
}

use crate::types::{Alg, Format};

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintError::Missing(field) => {
                write!(f, "obsigil mint: missing required field `{field}`")
            }
            MintError::EmptyAudience => {
                f.write_str("obsigil mint: `aud` must be a non-empty array")
            }
            MintError::UnsupportedAlg(a) => {
                write!(f, "obsigil mint: algorithm `{}` not enabled", a.code())
            }
            MintError::UnsupportedFormat(fmt) => {
                write!(
                    f,
                    "obsigil mint: serialization `{}` not enabled",
                    fmt.tag() as char
                )
            }
            MintError::Serialization(msg) => write!(f, "obsigil mint: serialization failed: {msg}"),
        }
    }
}

impl std::error::Error for MintError {}
