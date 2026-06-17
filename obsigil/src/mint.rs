//! Minting — the trusted issuer side (spec §4). Configure an [`Issuer`]
//! once with the secret key and defaults, mint many tokens. Errors are
//! descriptive: minting is not bearer-facing, so detail is not an oracle.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use uuid::Uuid;

use crate::aead::seal;
use crate::encoding::{encode_into, encoded_len};
use crate::error::MintError;
use crate::key::MandateKey;
use crate::reserved::{Claims, Clauses};
use crate::serial::to_plaintext;
use crate::types::{Alg, Encoding, Format, NumericDate, MANIFEST_KEY};

/// A configured token issuer. Holds the secret mandate key and the default
/// algorithm/serialization/encoding for the tokens it mints. Mint under one
/// key (create more issuers to mint under others).
pub struct Issuer {
    key: MandateKey,
    mandate_alg: Alg,
    mandate_format: Format,
    manifest_alg: Alg,
    manifest_format: Format,
    encoding: Encoding,
}

impl Issuer {
    /// A new issuer with spec defaults: AES-SIV (code 0), JSON, and the
    /// `.`/b64 encoding for the whole token.
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use obsigil::{Issuer, MandateKey, NoApp};
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    /// let token = Issuer::new(key)
    ///     .mandate(&NoApp::default())
    ///     .exp(4_000_000_000)
    ///     .mint()?;
    /// assert!(token.starts_with('.')); // mandate-only: no manifest half
    /// # Ok(()) }
    /// ```
    pub fn new(key: MandateKey) -> Self {
        Issuer {
            key,
            mandate_alg: Alg::Siv,
            mandate_format: Format::Json,
            manifest_alg: Alg::Siv,
            manifest_format: Format::Json,
            encoding: Encoding::B64,
        }
    }

    /// Set the mandate's algorithm code (default [`Alg::Siv`]).
    pub fn alg(mut self, alg: Alg) -> Self {
        self.mandate_alg = alg;
        self
    }

    /// Set the mandate's serialization (default [`Format::Json`]).
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # #[cfg(feature = "cbor")]
    /// # {
    /// use obsigil::{Format, Issuer, MandateKey, NoApp, Verifier};
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .format(Format::Cbor) // serialize the mandate as CBOR
    ///     .mandate(&NoApp::default())
    ///     .exp(4_000_000_000)
    ///     .mint()?;
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    /// assert!(Verifier::new().key(&key).now(1_000_000_000)
    ///     .verify::<NoApp>(&token).is_ok());
    /// # }
    /// # Ok(()) }
    /// ```
    pub fn format(mut self, format: Format) -> Self {
        self.mandate_format = format;
        self
    }

    /// Set the manifest's algorithm code (default [`Alg::Siv`]).
    pub fn manifest_alg(mut self, alg: Alg) -> Self {
        self.manifest_alg = alg;
        self
    }

    /// Set the manifest's serialization (default [`Format::Json`]).
    pub fn manifest_format(mut self, format: Format) -> Self {
        self.manifest_format = format;
        self
    }

    /// Set the token-wide text encoding (default [`Encoding::B64`]).
    pub fn encoding(mut self, encoding: Encoding) -> Self {
        self.encoding = encoding;
        self
    }

    /// Begin minting a mandate carrying the application clauses `app`. Use
    /// [`crate::NoApp`] for a mandate with only reserved clauses.
    pub fn mandate<'a, T: Serialize>(&'a self, app: &'a T) -> MintBuilder<'a, T> {
        MintBuilder {
            issuer: self,
            app,
            exp: None,
            tid: None,
            iss: None,
            aud: None,
            sub: None,
            manifest_plain: None,
        }
    }
}

/// Builder for a single token. `exp` is required; `tid` defaults to a fresh
/// UUIDv7 (spec §11.3).
pub struct MintBuilder<'a, T> {
    issuer: &'a Issuer,
    app: &'a T,
    exp: Option<NumericDate>,
    tid: Option<Uuid>,
    iss: Option<String>,
    aud: Option<Vec<String>>,
    sub: Option<String>,
    manifest_plain: Option<Result<Vec<u8>, MintError>>,
}

impl<'a, T: Serialize> MintBuilder<'a, T> {
    /// Set the authoritative expiry as an absolute NumericDate (spec §11.1).
    pub fn exp(mut self, exp: NumericDate) -> Self {
        self.exp = Some(exp);
        self
    }

    /// Set the expiry as a duration from now (spec §11.1).
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::time::Duration;
    /// use obsigil::{Issuer, MandateKey, NoApp, Verifier};
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .mandate(&NoApp::default())
    ///     .expires_in(Duration::from_secs(3600)) // valid for one hour
    ///     .mint()?;
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    /// assert!(Verifier::new().key(&key).verify::<NoApp>(&token).is_ok());
    /// # Ok(()) }
    /// ```
    pub fn expires_in(mut self, ttl: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as NumericDate)
            .unwrap_or(0);
        self.exp = Some(now + ttl.as_secs() as NumericDate);
        self
    }

    /// Override the auto-generated UUIDv7 `tid` (spec §11.3).
    pub fn tid(mut self, tid: Uuid) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Set the mandate's `iss` clause, for audit (spec §11.2).
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// Set the `aud` clause — the intended verifiers (spec §11.4). Must be
    /// non-empty.
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use obsigil::{Issuer, MandateKey, NoApp, Verifier};
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .mandate(&NoApp::default())
    ///     .exp(4_000_000_000)
    ///     .audience(["api", "admin-api"])
    ///     .mint()?;
    /// let key = MandateKey::from_bytes([42u8; 64])?;
    /// // A verifier in the audience succeeds; one outside fails.
    /// assert!(Verifier::new().key(&key).audience("api").now(1_000_000_000)
    ///     .verify::<NoApp>(&token).is_ok());
    /// assert!(Verifier::new().key(&key).audience("other").now(1_000_000_000)
    ///     .verify::<NoApp>(&token).is_err());
    /// # Ok(()) }
    /// ```
    pub fn audience<I, S>(mut self, audiences: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.aud = Some(audiences.into_iter().map(Into::into).collect());
        self
    }

    /// Set the `sub` clause — the subject authorized (spec §11.5).
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Attach a public manifest half with the required `iss` claim and the
    /// application claims `claims` (spec §4.2, §11.2). Sealed keyless under
    /// the public manifest key.
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use obsigil::{open_manifest, Issuer, MandateKey, Manifest, NoApp};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize)]
    /// struct Ui { theme: String }
    ///
    /// let token = Issuer::new(MandateKey::from_bytes([42u8; 64])?)
    ///     .mandate(&NoApp::default())
    ///     .exp(4_000_000_000)
    ///     .manifest("auth.example", &Ui { theme: "dark".into() })
    ///     .mint()?;
    ///
    /// // Opens with no secret — advisory only (spec §9.6).
    /// let manifest: Manifest<Ui> = open_manifest(&token).expect("present");
    /// assert_eq!(manifest.issuer(), "auth.example");
    /// assert_eq!(manifest.app().theme, "dark");
    /// # Ok(()) }
    /// ```
    pub fn manifest<M: Serialize>(mut self, iss: impl Into<String>, claims: &M) -> Self {
        let wire = Claims {
            iss: iss.into(),
            exp: None,
            app: claims,
        };
        self.manifest_plain = Some(to_plaintext(&wire, self.issuer.manifest_format));
        self
    }

    /// Mint the token (spec §3, §4). Errors if `exp` is unset, `aud` is
    /// empty, or a chosen algorithm/serialization is not built in.
    pub fn mint(self) -> Result<String, MintError> {
        let exp = self.exp.ok_or(MintError::Missing("exp"))?;
        if let Some(aud) = &self.aud {
            if aud.is_empty() {
                return Err(MintError::EmptyAudience);
            }
        }
        let tid = self.tid.unwrap_or_else(Uuid::now_v7);

        let clauses = Clauses {
            exp: Some(exp),
            tid: Some(tid),
            iss: self.iss,
            aud: self.aud,
            sub: self.sub,
            app: self.app,
        };
        // Seal both halves first (the manifest is optional).
        let mandate_plain = to_plaintext(&clauses, self.issuer.mandate_format)?;
        let mandate_sealed = seal(&mandate_plain, self.issuer.key.bytes(), self.issuer.mandate_alg)?;
        let manifest_sealed = match self.manifest_plain {
            Some(result) => Some(seal(&result?, &MANIFEST_KEY, self.issuer.manifest_alg)?),
            None => None,
        };

        // Assemble the token in a single allocation (spec §3):
        //   [ manifest_text manifest_code ] SEP mandate_code mandate_text
        let enc = self.issuer.encoding;
        let cap = manifest_sealed
            .as_ref()
            .map_or(0, |s| encoded_len(s.len(), enc) + 1) // text + code
            + 1 // separator
            + 1 // mandate algorithm code
            + encoded_len(mandate_sealed.len(), enc);
        let mut token = String::with_capacity(cap);
        if let Some(sealed) = &manifest_sealed {
            encode_into(sealed, enc, &mut token);
            token.push(self.issuer.manifest_alg.code());
        }
        token.push(enc.separator());
        token.push(self.issuer.mandate_alg.code());
        encode_into(&mandate_sealed, enc, &mut token);
        Ok(token)
    }
}
