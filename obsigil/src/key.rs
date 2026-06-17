//! The secret mandate key (spec §4.1).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::KeyError;
use crate::types::MANIFEST_KEY;

/// A secret 64-byte mandate master key (spec §4.1). Zeroized on drop; never
/// `Debug`/`Display` its bytes. One key both mints and verifies mandates
/// (spec §9.1).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MandateKey([u8; 64]);

impl MandateKey {
    /// Generate a fresh key from the platform CSPRNG (spec §4.1).
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
    /// an all-zero value (spec §4.1). The caller is responsible for the
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

    pub(crate) fn bytes(&self) -> &[u8; 64] {
        &self.0
    }
}
