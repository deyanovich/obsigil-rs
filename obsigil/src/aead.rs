//! Deterministic AEAD seal/open (spec §5). No random nonce, no associated
//! data. All RustCrypto usage is isolated to this file.
//!
//!   Code 0 (AES-SIV): the full 64-byte master is the AES-256-SIV key.
//!     Sealed with a ZERO-element associated-data vector (no AD
//!     components). Layout: synthetic-IV(16) || ciphertext (RFC 5297).
//!   Code 1 (AES-GCM-SIV): key = HKDF-Expand(master, "gcmsiv", 32) over
//!     HMAC-SHA-256 (Expand only). Sealed with a fixed all-zero 12-byte
//!     nonce, no AAD. Layout: ciphertext || tag(16) (RFC 8452).

use crate::error::MintError;
use crate::types::Alg;

/// Seal a half's plaintext (`tag || serialized-fields`) under a 64-byte
/// master with the AEAD named by `alg`. Errors only if `alg` is not
/// compiled into this build (spec §5).
pub fn seal(plaintext: &[u8], master: &[u8; 64], alg: Alg) -> Result<Vec<u8>, MintError> {
    match alg {
        Alg::Siv => Ok(seal_siv(plaintext, master)),
        Alg::GcmSiv => seal_gcm_siv(plaintext, master),
    }
}

/// Open a sealed half under a 64-byte master. `None` on authentication
/// failure or an algorithm code this build does not implement. Never
/// panics on bad ciphertext.
pub fn open(sealed: &[u8], master: &[u8; 64], alg: Alg) -> Option<Vec<u8>> {
    match alg {
        Alg::Siv => open_siv(sealed, master),
        Alg::GcmSiv => open_gcm_siv(sealed, master),
    }
}

fn seal_siv(plaintext: &[u8], master: &[u8; 64]) -> Vec<u8> {
    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit;
    let mut cipher = Aes256Siv::new(master.into());
    let headers: [&[u8]; 0] = []; // zero-element AD vector (spec §5.2)
    cipher.encrypt(headers, plaintext).expect("SIV encrypt")
}

fn open_siv(sealed: &[u8], master: &[u8; 64]) -> Option<Vec<u8>> {
    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit;
    let mut cipher = Aes256Siv::new(master.into());
    let headers: [&[u8]; 0] = [];
    cipher.decrypt(headers, sealed).ok()
}

#[cfg(feature = "gcm-siv")]
fn gcm_siv_key(master: &[u8; 64]) -> zeroize::Zeroizing<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    // HKDF-Expand only: master IS the PRK (already uniformly random),
    // info = "gcmsiv", L = 32 (spec §5.1). No Extract step. The derived
    // subkey is wrapped in `Zeroizing` so it is wiped on drop.
    let hk = Hkdf::<Sha256>::from_prk(master).expect("PRK >= 32 bytes");
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(b"gcmsiv", &mut okm[..]).expect("32-byte OKM");
    okm
}

#[cfg(feature = "gcm-siv")]
fn seal_gcm_siv(plaintext: &[u8], master: &[u8; 64]) -> Result<Vec<u8>, MintError> {
    use aes_gcm_siv::aead::Aead;
    use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
    let key = gcm_siv_key(master);
    let cipher = Aes256GcmSiv::new((&*key).into());
    let nonce = Nonce::from_slice(&[0u8; 12]); // fixed nonce (spec §5.2)
    Ok(cipher.encrypt(nonce, plaintext).expect("GCM-SIV encrypt"))
}

#[cfg(not(feature = "gcm-siv"))]
fn seal_gcm_siv(_plaintext: &[u8], _master: &[u8; 64]) -> Result<Vec<u8>, MintError> {
    Err(MintError::UnsupportedAlg(Alg::GcmSiv))
}

#[cfg(feature = "gcm-siv")]
fn open_gcm_siv(sealed: &[u8], master: &[u8; 64]) -> Option<Vec<u8>> {
    use aes_gcm_siv::aead::Aead;
    use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
    let key = gcm_siv_key(master);
    let cipher = Aes256GcmSiv::new((&*key).into());
    let nonce = Nonce::from_slice(&[0u8; 12]);
    cipher.decrypt(nonce, sealed).ok()
}

#[cfg(not(feature = "gcm-siv"))]
fn open_gcm_siv(_sealed: &[u8], _master: &[u8; 64]) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siv_round_trips_and_detects_tampering() {
        let master = [7u8; 64];
        let pt = b"jhello mandate";
        let sealed = seal(pt, &master, Alg::Siv).unwrap();
        assert_eq!(sealed.len(), 16 + pt.len()); // IV(16) || ct
        assert_eq!(open(&sealed, &master, Alg::Siv).as_deref(), Some(&pt[..]));

        let mut bad = sealed.clone();
        bad[20] ^= 0x01;
        assert_eq!(open(&bad, &master, Alg::Siv), None);

        let wrong = [9u8; 64];
        assert_eq!(open(&sealed, &wrong, Alg::Siv), None);
    }

    #[cfg(feature = "gcm-siv")]
    #[test]
    fn gcm_siv_round_trips() {
        let master = [3u8; 64];
        let pt = b"jhello mandate";
        let sealed = seal(pt, &master, Alg::GcmSiv).unwrap();
        assert_eq!(sealed.len(), pt.len() + 16); // ct || tag(16)
        assert_eq!(
            open(&sealed, &master, Alg::GcmSiv).as_deref(),
            Some(&pt[..])
        );
    }
}
