//! Strict, canonical text codecs (spec §3), backed by `data_encoding`.
//! Decoders reject any non-canonical input — padding, whitespace,
//! out-of-alphabet characters, non-zero trailing b64 bits, bad lengths —
//! by returning `None`.

use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

use crate::types::Encoding;

/// Exact text length of `n` sealed bytes under `encoding` (spec §3).
pub fn encoded_len(n: usize, encoding: Encoding) -> usize {
    match encoding {
        Encoding::B64 => BASE64URL_NOPAD.encode_len(n),
        Encoding::Hex => HEXLOWER.encode_len(n),
    }
}

/// Append a half's ciphertext bytes, text-encoded, to `out`.
pub fn encode_into(bytes: &[u8], encoding: Encoding, out: &mut String) {
    match encoding {
        Encoding::B64 => BASE64URL_NOPAD.encode_append(bytes, out),
        Encoding::Hex => HEXLOWER.encode_append(bytes, out),
    }
}

/// Decode a half's ciphertext text under the token's encoding. `None` on
/// any non-canonical input (spec §3).
pub fn decode(text: &str, encoding: Encoding) -> Option<Vec<u8>> {
    match encoding {
        Encoding::B64 => BASE64URL_NOPAD.decode(text.as_bytes()).ok(),
        Encoding::Hex => HEXLOWER.decode(text.as_bytes()).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_round_trips_all_lengths() {
        for n in 0..=8usize {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let mut text = String::new();
            encode_into(&bytes, Encoding::B64, &mut text);
            assert_eq!(text.len(), encoded_len(bytes.len(), Encoding::B64));
            assert!(!text.contains(['=', '.', '~']));
            assert_eq!(decode(&text, Encoding::B64).as_deref(), Some(&bytes[..]));
        }
    }

    #[test]
    fn b64_rejects_non_canonical() {
        assert_eq!(decode("AAAAA", Encoding::B64), None); // length 1 mod 4
        assert_eq!(decode("AA==", Encoding::B64), None); // padding
        assert_eq!(decode("AB", Encoding::B64), None); // non-zero trailing bits
        assert_eq!(decode("AAB", Encoding::B64), None); // non-zero trailing bits
        assert_eq!(decode("A*BC", Encoding::B64), None); // out of alphabet
        assert_eq!(decode("AA AA", Encoding::B64), None); // whitespace
        assert_eq!(decode("AA", Encoding::B64), Some(vec![0])); // canonical
    }

    #[test]
    fn hex_round_trips_and_rejects() {
        let bytes = [0x00u8, 0x0f, 0xa9, 0xff, 0x10];
        let mut hex = String::new();
        encode_into(&bytes, Encoding::Hex, &mut hex);
        assert_eq!(hex, "000fa9ff10");
        assert_eq!(decode("000fa9ff10", Encoding::Hex).as_deref(), Some(&bytes[..]));
        assert_eq!(decode("abc", Encoding::Hex), None); // odd length
        assert_eq!(decode("AB", Encoding::Hex), None); // uppercase
        assert_eq!(decode("zz", Encoding::Hex), None); // out of alphabet
    }
}
