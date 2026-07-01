//! The secret mandate key (the mandate construction, §5.1).

use data_encoding::HEXLOWER;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::encoding::decode;
use crate::error::KeyError;
use crate::types::{Encoding, MANIFEST_KEY};

/// A secret 64-byte mandate master key (the mandate construction, §5.1). Zeroized on drop; never
/// `Debug`/`Display` its bytes. One key both mints and verifies mandates
/// (the symmetric-key property of the Security Considerations, §16.1).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MandateKey([u8; 64]);

impl MandateKey {
    /// Generate a fresh key from the platform CSPRNG (the mandate construction, §5.1).
    ///
    /// ```rust
    /// use obsigil::MandateKey;
    /// // 64 bytes from the OS CSPRNG, zeroized on drop.
    /// let key = MandateKey::generate();
    /// # let _ = key;
    /// ```
    pub fn generate() -> Self {
        let mut bytes = [0u8; 64];
        getrandom::getrandom(&mut bytes).expect("platform CSPRNG unavailable");
        MandateKey(bytes)
    }

    /// Wrap 64 bytes as a mandate key. Rejects the public manifest key and
    /// an all-zero value (the mandate construction, §5.1). The caller is responsible for the
    /// bytes being uniformly random from a CSPRNG.
    ///
    /// ```rust
    /// use obsigil::{MandateKey, MANIFEST_KEY};
    /// assert!(MandateKey::from_bytes([7u8; 64]).is_ok());
    /// assert!(MandateKey::from_bytes(MANIFEST_KEY).is_err()); // the public key
    /// assert!(MandateKey::from_bytes([0u8; 64]).is_err());    // all zero
    /// ```
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, KeyError> {
        if bytes == MANIFEST_KEY {
            return Err(KeyError::IsManifestKey);
        }
        if bytes == [0u8; 64] {
            return Err(KeyError::AllZero);
        }
        Ok(MandateKey(bytes))
    }

    /// Parse a mandate key from its canonical text form: 128 lowercase hex
    /// digits (the Key format, §6.2). This is the default way to supply a key
    /// — the form it is stored and provisioned in (a secret environment
    /// variable, a secrets-manager value) — so the string feeds straight in;
    /// [`from_bytes`](Self::from_bytes) is the raw-octet alternative. The key
    /// material is the 64 decoded bytes, not the hex characters. Rejects the
    /// public manifest key and an all-zero value, exactly as
    /// [`from_bytes`](Self::from_bytes).
    ///
    /// A malformed key — not exactly 128 lowercase hex digits — is returned as
    /// a distinct [`KeyError`], never the verifier's opaque failure: a bad key
    /// is an operator misconfiguration, not a token rejection (the Key format,
    /// §6.2).
    ///
    /// ```rust
    /// use obsigil::MandateKey;
    /// let hex = "2a".repeat(64);            // 128 lowercase hex digits
    /// assert!(MandateKey::from_hex(&hex).is_ok());
    /// let upper = "2A".repeat(64);
    /// assert!(MandateKey::from_hex(&upper).is_err()); // uppercase rejected
    /// assert!(MandateKey::from_hex("2a").is_err());   // wrong length
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let decoded =
            zeroize::Zeroizing::new(decode(hex, Encoding::Hex).ok_or(KeyError::BadHexEncoding)?);
        let bytes: [u8; 64] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::BadHexLength { got: decoded.len() })?;
        Self::from_bytes(bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Generate a fresh mandate key as its canonical text form — 128 lowercase
/// hex digits (the Key format, §6.2) — drawn from the platform CSPRNG. This is
/// the form to store as a secret (an environment variable, a secrets-manager
/// value) and later load with [`MandateKey::from_hex`]. For a key used
/// in-memory without a text round-trip, [`MandateKey::generate`] returns the
/// opaque key directly.
///
/// ```rust
/// use obsigil::{generate_key, MandateKey};
/// let hex = generate_key();
/// assert_eq!(hex.len(), 128);
/// let key = MandateKey::from_hex(&hex).expect("canonical lowercase hex");
/// # let _ = key;
/// ```
pub fn generate_key() -> String {
    let mut bytes = zeroize::Zeroizing::new([0u8; 64]);
    getrandom::getrandom(&mut bytes[..]).expect("platform CSPRNG unavailable");
    HEXLOWER.encode(&bytes[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_hex_accepts_canonical_lowercase() {
        assert!(MandateKey::from_hex(&"2a".repeat(64)).is_ok());
    }

    // `MandateKey` has no `Debug` (its bytes must never print), so assert on
    // the error via `.err()`, which drops the `Ok` value.
    #[test]
    fn from_hex_rejects_uppercase_and_bad_length() {
        // Uppercase is not canonical (§6.2): rejected, no lowercasing.
        assert_eq!(
            MandateKey::from_hex(&"2A".repeat(64)).err(),
            Some(KeyError::BadHexEncoding)
        );
        // Valid hex, wrong decoded length.
        assert_eq!(
            MandateKey::from_hex("2a2a2a").err(),
            Some(KeyError::BadHexLength { got: 3 })
        );
        // Odd length is not canonical hex at all.
        assert_eq!(
            MandateKey::from_hex("2a2").err(),
            Some(KeyError::BadHexEncoding)
        );
    }

    #[test]
    fn from_hex_rejects_manifest_and_zero() {
        assert_eq!(
            MandateKey::from_hex(&HEXLOWER.encode(&MANIFEST_KEY)).err(),
            Some(KeyError::IsManifestKey)
        );
        assert_eq!(
            MandateKey::from_hex(&"00".repeat(64)).err(),
            Some(KeyError::AllZero)
        );
    }

    #[test]
    fn generate_key_is_canonical_hex_that_round_trips() {
        let hex = generate_key();
        assert_eq!(hex.len(), 128);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert!(MandateKey::from_hex(&hex).is_ok());
    }
}
