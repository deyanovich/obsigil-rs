//! Low-level conformance surface (the Conformance and test vectors section, §13), behind the `conformance`
//! feature. Byte-level seal/open/encode/decode/parse on raw octets, for
//! generating and checking the language-agnostic test vectors. This is not
//! the everyday API — mint and verify are. A positive vector reproduces by
//! sealing the given octets and matching the byte string; this module is
//! the entry point that makes that possible without a serializer. The octets
//! are a half's canonical CBOR plaintext (the Serialization rules, §7).

use crate::aead;
use crate::encoding as enc;
use crate::token;

pub use crate::types::{Alg, Encoding, MANIFEST_KEY};

/// Seal raw octets (a half's canonical CBOR plaintext) under a 64-byte key
/// with `alg`. `None` if `alg` is not compiled into this build (the Algorithm registry, §6).
pub fn seal(octets: &[u8], key: &[u8; 64], alg: Alg) -> Option<Vec<u8>> {
    aead::seal(octets, key, alg).ok()
}

/// Open a sealed half to its raw octets. `None` on authentication failure
/// or an unimplemented algorithm.
pub fn open(sealed: &[u8], key: &[u8; 64], alg: Alg) -> Option<Vec<u8>> {
    aead::open(sealed, key, alg)
}

/// Text-encode sealed bytes under a token encoding (the Token structure section, §4).
pub fn encode(bytes: &[u8], encoding: Encoding) -> String {
    let mut out = String::new();
    enc::encode_into(bytes, encoding, &mut out);
    out
}

/// Strict-decode a half's ciphertext text (the Token structure section, §4). `None` on any
/// non-canonical input.
pub fn decode(text: &str, encoding: Encoding) -> Option<Vec<u8>> {
    enc::decode(text, encoding)
}

/// A present half in a parsed token: its algorithm-code character and its
/// still-text ciphertext.
#[derive(Clone, Debug)]
pub struct Half {
    pub alg: char,
    pub text: String,
}

/// A structurally parsed token (owned). Either half may be absent.
#[derive(Clone, Debug)]
pub struct Parsed {
    pub encoding: Encoding,
    pub separator: char,
    pub manifest: Option<Half>,
    pub mandate: Option<Half>,
    pub mandate_part: String,
}

/// Parse a token structurally (the Token structure section, §4). `None` if malformed.
pub fn parse(token: &str) -> Option<Parsed> {
    let p = token::parse(token).ok()?;
    let half = |h: token::Half<'_>| Half {
        alg: h.alg_code,
        text: h.text.to_string(),
    };
    Some(Parsed {
        encoding: p.encoding,
        separator: p.separator,
        manifest: p.manifest.map(half),
        mandate: p.mandate.map(half),
        mandate_part: p.mandate_part.to_string(),
    })
}
