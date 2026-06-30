//! Format-level enumerations and constants (the Token structure section, §4; the published manifest key, §5.2; the Algorithm registry, §6; the Serialization rules, §7).

use uuid::Uuid;

/// Seconds since the Unix epoch (JWT NumericDate); the type of `exp`.
pub type NumericDate = i64;

/// The AEAD that seals a half, named by its single-character algorithm
/// code in the clear next to the separator (the Algorithm registry, §6).
///
/// ```rust
/// use obsigil::Alg;
/// assert_eq!(Alg::Siv.code(), '0');
/// assert_eq!(Alg::from_code('0'), Some(Alg::Siv));
/// assert_eq!(Alg::from_code('z'), None); // a code this build does not implement
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Alg {
    /// Code `0` — AES-SIV (RFC 5297). Mandatory to implement.
    Siv,
    /// Code `1` — AES-GCM-SIV (RFC 8452). Optional (`gcm-siv` feature).
    GcmSiv,
}

impl Alg {
    /// The clear-text code character for this algorithm.
    pub fn code(self) -> char {
        match self {
            Alg::Siv => '0',
            Alg::GcmSiv => '1',
        }
    }

    /// Parse an algorithm code character. Returns `None` for any code this
    /// build does not implement (the Algorithm registry, §6).
    pub fn from_code(c: char) -> Option<Alg> {
        match c {
            '0' => Some(Alg::Siv),
            '1' => Some(Alg::GcmSiv),
            _ => None,
        }
    }
}

/// A token's text encoding, selected for the whole token by the separator
/// (the Token structure section, §4): `.` => b64, `~` => hex.
///
/// ```rust
/// use obsigil::Encoding;
/// assert_eq!(Encoding::B64.separator(), '.');
/// assert_eq!(Encoding::from_separator('~'), Some(Encoding::Hex));
/// assert_eq!(Encoding::from_separator('!'), None);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Encoding {
    /// URL-safe base64, no padding. Separator `.`.
    B64,
    /// Lowercase hex. Separator `~`.
    Hex,
}

impl Encoding {
    /// The separator character that names this encoding.
    pub fn separator(self) -> char {
        match self {
            Encoding::B64 => '.',
            Encoding::Hex => '~',
        }
    }

    /// Map a separator character to its encoding.
    pub fn from_separator(c: char) -> Option<Encoding> {
        match c {
            '.' => Some(Encoding::B64),
            '~' => Some(Encoding::Hex),
            _ => None,
        }
    }
}

/// The public 64-byte manifest key pinned by the spec (the published manifest key, §5.2). Every
/// conformant implementation MUST use this exact value. It is public: it
/// opens *and* forges manifests, which is the point — the manifest is an
/// encoding wrapper, not a security layer.
pub const MANIFEST_KEY: [u8; 64] = [
    0x38, 0x12, 0x84, 0x63, 0x3d, 0x02, 0xea, 0x5f, //
    0x35, 0xdf, 0x85, 0x96, 0xb5, 0xcc, 0x42, 0x18, //
    0x31, 0x00, 0x60, 0x46, 0x8e, 0x8b, 0x46, 0x54, //
    0x55, 0xa4, 0x15, 0x17, 0x4e, 0xa6, 0xe9, 0x66, //
    0xa9, 0xf4, 0x8e, 0xec, 0x4b, 0xa4, 0x46, 0xdd, //
    0xfc, 0x8b, 0x78, 0x58, 0x78, 0x95, 0x35, 0x6f, //
    0x45, 0xa7, 0x5a, 0x1a, 0xb7, 0x41, 0x94, 0x54, //
    0xdd, 0x9f, 0x7a, 0xa8, 0xa9, 0x5d, 0xbd, 0xd5, //
];

/// The mandate's issue time, derived from a UUIDv7 `tid` (the `tid` field, §8.2): the
/// 48-bit big-endian Unix-millisecond field, floored to whole seconds for
/// NumericDate semantics. obsigil defines no separate `iat`.
///
/// ```rust
/// use obsigil::{tid_issued_at, Uuid};
/// // A UUIDv7 whose 48-bit timestamp field is 1000 ms.
/// let tid = Uuid::from_bytes([
///     0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x70, 0x00,
///     0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/// ]);
/// assert_eq!(tid_issued_at(tid), 1); // 1000 ms -> 1 second
/// ```
pub fn tid_issued_at(tid: Uuid) -> NumericDate {
    let b = tid.as_bytes();
    let ms = (u64::from(b[0]) << 40)
        | (u64::from(b[1]) << 32)
        | (u64::from(b[2]) << 24)
        | (u64::from(b[3]) << 16)
        | (u64::from(b[4]) << 8)
        | u64::from(b[5]);
    (ms / 1000) as NumericDate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_key_matches_spec_hex() {
        let mut hex = String::new();
        crate::encoding::encode_into(&MANIFEST_KEY, Encoding::Hex, &mut hex);
        assert_eq!(
            hex,
            "381284633d02ea5f35df8596b5cc4218310060468e8b465455a415174ea6e966\
             a9f48eec4ba446ddfc8b78587895356f45a75a1ab7419454dd9f7aa8a95dbdd5"
        );
    }

    #[test]
    fn tid_issued_at_reads_the_48_bit_ms_field() {
        // First 6 bytes = 0x0000_0001_86A0 = 100_000 ms -> 100 s.
        let tid = Uuid::from_bytes([
            0x00, 0x00, 0x00, 0x01, 0x86, 0xa0, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        assert_eq!(tid_issued_at(tid), 100);
    }
}
