//! Token grammar: split a token into halves and read each present half's
//! algorithm-code character (spec §3). Purely structural — no decoding,
//! decryption, or registry check. Algorithm codes are read positionally
//! (a valid `0`-`9`/`a`-`z` char), so a code accepted here may still be
//! unimplemented.

use crate::types::Encoding;

/// A present half: its raw algorithm-code character and its still-text
/// ciphertext (in the token's encoding).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Half<'a> {
    pub alg_code: char,
    pub text: &'a str,
}

/// A structurally well-formed token. Either half may be absent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Parsed<'a> {
    pub encoding: Encoding,
    pub separator: char,
    pub manifest: Option<Half<'a>>,
    pub mandate: Option<Half<'a>>,
    /// The post-separator part exactly as received (`ALG mandate`, or "").
    /// The forwardable mandate-only token is `separator + mandate_part`.
    pub mandate_part: &'a str,
}

/// Why a token failed structural parsing. Diagnostic only — every cause
/// collapses to a uniform failure at the bearer-facing boundary (spec §9.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    Empty,
    SeparatorCount,
    DegenerateHalf,
    BothAbsent,
    BadAlgChar,
}

/// ALG = %x30-39 | %x61-7A : one char `0`-`9` or `a`-`z` (spec §3).
fn is_alg_char(c: char) -> bool {
    c.is_ascii_digit() || c.is_ascii_lowercase()
}

/// Parse a token into its halves (spec §3).
pub fn parse(input: &str) -> Result<Parsed<'_>, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut sep_index = None;
    let mut sep_char = '\0';
    let mut sep_count = 0usize;
    for (i, ch) in input.char_indices() {
        if ch == '.' || ch == '~' {
            sep_count += 1;
            sep_index = Some(i);
            sep_char = ch;
        }
    }
    if sep_count != 1 {
        return Err(ParseError::SeparatorCount);
    }
    let sep_index = sep_index.expect("exactly one separator");
    let encoding = Encoding::from_separator(sep_char).expect("separator is . or ~");

    let before = &input[..sep_index];
    let after = &input[sep_index + 1..];

    // Manifest part: ciphertext then its algorithm code (the LAST char).
    let manifest = if before.is_empty() {
        None
    } else {
        let code = before.chars().next_back().expect("non-empty");
        let text = &before[..before.len() - code.len_utf8()];
        if text.is_empty() {
            return Err(ParseError::DegenerateHalf); // lone code, empty ciphertext
        }
        if !is_alg_char(code) {
            return Err(ParseError::BadAlgChar);
        }
        Some(Half {
            alg_code: code,
            text,
        })
    };

    // Mandate part: algorithm code (the FIRST char) then ciphertext.
    let mandate = if after.is_empty() {
        None
    } else {
        let code = after.chars().next().expect("non-empty");
        let text = &after[code.len_utf8()..];
        if text.is_empty() {
            return Err(ParseError::DegenerateHalf);
        }
        if !is_alg_char(code) {
            return Err(ParseError::BadAlgChar);
        }
        Some(Half {
            alg_code: code,
            text,
        })
    };

    if manifest.is_none() && mandate.is_none() {
        return Err(ParseError::BothAbsent);
    }

    Ok(Parsed {
        encoding,
        separator: sep_char,
        manifest,
        mandate,
        mandate_part: after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_three_shapes() {
        let full = parse("abc0.0def").unwrap();
        assert_eq!(full.encoding, Encoding::B64);
        assert_eq!(
            full.manifest,
            Some(Half {
                alg_code: '0',
                text: "abc"
            })
        );
        assert_eq!(
            full.mandate,
            Some(Half {
                alg_code: '0',
                text: "def"
            })
        );
        assert_eq!(full.mandate_part, "0def");

        let manifest_only = parse("abc0.").unwrap();
        assert!(manifest_only.mandate.is_none());
        assert_eq!(manifest_only.mandate_part, "");
    }

    #[test]
    fn mandate_only_and_hex() {
        let t = parse(".0def").unwrap();
        assert!(t.manifest.is_none());
        assert_eq!(
            t.mandate,
            Some(Half {
                alg_code: '0',
                text: "def"
            })
        );

        let hex = parse("abc0~1def").unwrap();
        assert_eq!(hex.encoding, Encoding::Hex);
        assert_eq!(
            hex.mandate,
            Some(Half {
                alg_code: '1',
                text: "def"
            })
        );
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse(""), Err(ParseError::Empty));
        assert_eq!(parse("abc"), Err(ParseError::SeparatorCount));
        assert_eq!(parse("a.b.c"), Err(ParseError::SeparatorCount));
        assert_eq!(parse("."), Err(ParseError::BothAbsent));
        assert_eq!(parse("0."), Err(ParseError::DegenerateHalf));
        assert_eq!(parse(".0"), Err(ParseError::DegenerateHalf));
        assert_eq!(parse("ab-."), Err(ParseError::BadAlgChar));
        assert_eq!(parse("abZ."), Err(ParseError::BadAlgChar));
    }
}
