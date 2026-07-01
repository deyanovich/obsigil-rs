//! Integration tests over the public API (the Conformance and test vectors section, §13): a positive round-trip
//! and the required negative cases.

use std::time::Duration;

use obsigil::{
    claims, Claims, Clauses, Issuer, MandateKey, MintError, NoApp, Reason, Uuid, Verifier,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ClauseData {
    role: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct ClaimData {
    theme: String,
}

const KEY_BYTES: [u8; 64] = [42u8; 64];

fn issuer() -> Issuer {
    Issuer::new(MandateKey::from_bytes(KEY_BYTES).unwrap())
}

fn full_token() -> String {
    issuer()
        .clauses(&ClauseData {
            role: "admin".into(),
        })
        .exp(4_000_000_000)
        .audience(["api"])
        .subject("u42")
        .manifest(
            "auth.example",
            &ClaimData {
                theme: "dark".into(),
            },
        )
        .mint()
        .unwrap()
}

#[test]
fn full_token_round_trips() {
    let token = full_token();

    // Front-end advisory view (keyless).
    let advisory: Claims<ClaimData> = claims(&token).unwrap();
    assert_eq!(advisory.issuer(), "auth.example");
    assert_eq!(advisory.iss(), "auth.example"); // short alias
    assert_eq!(advisory.app().theme, "dark");

    // Backend verification (authoritative).
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let verifier = Verifier::new().key(&key).audience("api").now(1_000_000_000);
    let mandate: Clauses<ClauseData> = verifier.clauses(&token).unwrap();
    assert_eq!(mandate.app().role, "admin");
    assert_eq!(mandate.subject(), Some("u42"));
    assert_eq!(mandate.sub(), Some("u42")); // short alias
    assert_eq!(mandate.aud(), Some(&["api".to_string()][..])); // short alias
    assert_eq!(mandate.exp(), 4_000_000_000);
    assert_eq!(mandate.tid().get_version_num(), 7);
}

#[test]
fn verifies_the_forwarded_mandate_only_form() {
    let token = full_token();
    let sep = token.find(['.', '~']).unwrap();
    let forwarded = &token[sep..]; // ".0<mandate>" — the Audiences forward form (§9)
    assert!(forwarded.starts_with('.'));

    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let verifier = Verifier::new().key(&key).audience("api").now(1_000_000_000);
    assert!(verifier.clauses::<ClauseData>(forwarded).is_ok());
}

#[test]
fn trial_decryption_accepts_the_matching_key() {
    let token = full_token();
    let wrong = MandateKey::from_bytes([7u8; 64]).unwrap();
    let right = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let verifier = Verifier::new()
        .keys([&wrong, &right])
        .audience("api")
        .now(1_000_000_000);
    assert!(verifier.clauses::<ClauseData>(&token).is_ok());
}

#[test]
fn rejects_uniformly_with_internal_reasons() {
    let token = full_token();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let wrong = MandateKey::from_bytes([7u8; 64]).unwrap();

    // expired
    let v = Verifier::new().key(&key).audience("api").now(4_000_000_001);
    let e = v.clauses::<ClauseData>(&token).unwrap_err();
    assert_eq!(e.reason(), Reason::Expired);
    assert_eq!(e.to_string(), "obsigil: token rejected"); // uniform Display

    // aud mismatch (wrong audience)
    let v = Verifier::new()
        .key(&key)
        .audience("other")
        .now(1_000_000_000);
    assert_eq!(
        v.clauses::<ClauseData>(&token).unwrap_err().reason(),
        Reason::AudienceMismatch
    );

    // aud present but verifier has none
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.clauses::<ClauseData>(&token).unwrap_err().reason(),
        Reason::AudienceMismatch
    );

    // wrong key
    let v = Verifier::new()
        .key(&wrong)
        .audience("api")
        .now(1_000_000_000);
    assert_eq!(
        v.clauses::<ClauseData>(&token).unwrap_err().reason(),
        Reason::AuthFailed
    );

    // malformed
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.clauses::<ClauseData>("garbage").unwrap_err().reason(),
        Reason::Malformed
    );
}

// Seal a hand-built canonical-CBOR mandate map into a mandate-only token
// under KEY_BYTES, bypassing the (tid-validating) mint path so the verifier's
// own tid, type, and canonical-CBOR checks can be exercised on crafted input.
// Needs the byte-level `conformance` surface.
#[cfg(feature = "conformance")]
fn craft(entries: Vec<(ciborium::value::Value, ciborium::value::Value)>) -> String {
    use obsigil::lowlevel::{self, Alg, Encoding};
    let mut octets = Vec::new();
    ciborium::into_writer(&ciborium::value::Value::Map(entries), &mut octets).unwrap();
    let sealed = lowlevel::seal(&octets, &KEY_BYTES, Alg::Siv).unwrap();
    format!(".0{}", lowlevel::encode(&sealed, Encoding::B64))
}

#[cfg(feature = "conformance")]
fn ik(n: i8) -> ciborium::value::Value {
    ciborium::value::Value::Integer(n.into())
}

#[cfg(feature = "conformance")]
fn tid_bytes(s: &str) -> ciborium::value::Value {
    ciborium::value::Value::Bytes(Uuid::parse_str(s).unwrap().as_bytes().to_vec())
}

#[cfg(feature = "conformance")]
fn exp_val(n: i64) -> ciborium::value::Value {
    ciborium::value::Value::Integer(n.into())
}

#[cfg(feature = "conformance")]
#[test]
fn verifier_rejects_malformed_tid() {
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    // Canonical key order: -1 (0x20) before -2 (0x21).
    let reason = |tid: &str| {
        let token = craft(vec![
            (ik(-1), tid_bytes(tid)),
            (ik(-2), exp_val(4_000_000_000)),
        ]);
        Verifier::new()
            .key(&key)
            .now(1_000_000_000)
            .clauses::<NoApp>(&token)
            .unwrap_err()
            .reason()
    };
    // Wrong version (nil UUID, version 0).
    assert_eq!(
        reason("00000000-0000-0000-0000-000000000000"),
        Reason::BadTid
    );
    // Version 7 but a non-RFC-4122 variant (NCS, nibble 0) — the `tid` field (§8.2).
    assert_eq!(
        reason("019ed29a-378d-72f0-0462-4929cd2bfcad"),
        Reason::BadTid
    );
    // A well-formed v7 tid verifies.
    let good = craft(vec![
        (ik(-1), tid_bytes("019ed29a-378d-72f0-b462-4929cd2bfcad")),
        (ik(-2), exp_val(4_000_000_000)),
    ]);
    assert!(Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .clauses::<NoApp>(&good)
        .is_ok());
}

#[cfg(feature = "conformance")]
#[test]
fn verifier_rejects_noncanonical_cbor() {
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let tid = "019ed29a-378d-72f0-b462-4929cd2bfcad";
    let reason = |entries| {
        Verifier::new()
            .key(&key)
            .now(1_000_000_000)
            .clauses::<NoApp>(&craft(entries))
            .unwrap_err()
            .reason()
    };
    // A duplicate map key is non-canonical (forecloses last-wins/first-wins).
    assert_eq!(
        reason(vec![
            (ik(-1), tid_bytes(tid)),
            (ik(-2), exp_val(4_000_000_000)),
            (ik(-2), exp_val(1)),
        ]),
        Reason::NonCanonical
    );
    // Keys out of canonical order (-2 before -1) is non-canonical.
    assert_eq!(
        reason(vec![
            (ik(-2), exp_val(4_000_000_000)),
            (ik(-1), tid_bytes(tid))
        ]),
        Reason::NonCanonical
    );
    // An unrecognized negative key fails closed (obsigil's namespace).
    assert_eq!(
        reason(vec![
            (ik(-1), tid_bytes(tid)),
            (ik(-2), exp_val(4_000_000_000)),
            (ik(-9), exp_val(1)),
        ]),
        Reason::UnknownReservedKey
    );
}

// Rule 6 (the Serialization rules, §7): a CBOR text string carrying invalid UTF-8 is rejected.
// Asserted explicitly — hand-encoded, since ciborium's `Value::Text` is a
// Rust `String` and cannot represent invalid UTF-8 — so the property does not
// silently rest on whatever ciborium happens to do today.
#[cfg(feature = "conformance")]
#[test]
fn rejects_invalid_utf8_text_string() {
    use obsigil::lowlevel::{self, Alg, Encoding};
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    // Raw CBOR for the map {0: "<0xff>"}: A1 (map, 1 pair), 00 (key int 0),
    // 61 FF (text string, length 1, content byte 0xFF — not valid UTF-8).
    let octets = [0xA1u8, 0x00, 0x61, 0xFF];
    let sealed = lowlevel::seal(&octets, &KEY_BYTES, Alg::Siv).unwrap();
    let token = format!(".0{}", lowlevel::encode(&sealed, Encoding::B64));

    // Authenticates under the right key, but the plaintext is not valid CBOR
    // (the text string's bytes are not UTF-8), so both the enforcing and the
    // diagnostic decode terminals reject it.
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.clauses::<NoApp>(&token).unwrap_err().reason(),
        Reason::Malformed
    );
    assert_eq!(
        v.clauses_unchecked::<NoApp>(&token).unwrap_err().reason(),
        Reason::Malformed
    );
}

// The Serialization rules (§7): a CBOR map key that is not an integer or text string is rejected at
// EVERY map depth, not just the half's top-level map. Go cannot represent a
// byte-slice map key, so a *nested* map with one is a token no conformant
// verifier could decode. Hand-sealed because the property is on a key type
// minting never emits (ciborium's `Value::Map` can carry a `Value::Bytes` key,
// but the mint path never produces one) — so it rests on exact crafted octets.
#[cfg(feature = "conformance")]
#[test]
fn rejects_nested_byte_string_map_key() {
    use obsigil::lowlevel::{self, Alg, Encoding};
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    // map(3) { 0: {h'00': 1}, -1: <16-byte v7 tid>, -2: 4000000000 }. The
    // application value under key 0 is a nested map whose sole key is the
    // 1-byte byte string 0x00 — a disallowed map-key type at depth. The
    // top-level keys (0, -1, -2) are all valid integers, so the violation is
    // reachable only by recursing into the application value.
    let octets: [u8; 30] = [
        0xA3, 0x00, 0xA1, 0x41, 0x00, 0x01, 0x20, 0x50, 0x01, 0x9E, //
        0xD2, 0x9A, 0x37, 0x8D, 0x72, 0xF0, 0xB4, 0x62, 0x49, 0x29, //
        0xCD, 0x2B, 0xFC, 0xAD, 0x21, 0x1A, 0xEE, 0x6B, 0x28, 0x00, //
    ];
    let sealed = lowlevel::seal(&octets, &KEY_BYTES, Alg::Siv).unwrap();
    let token = format!(".0{}", lowlevel::encode(&sealed, Encoding::B64));

    // Authenticates under the right key, but the nested byte-string key is a
    // disallowed map-key type, so both decode terminals reject it.
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.clauses::<NoApp>(&token).unwrap_err().reason(),
        Reason::NonCanonical
    );
    assert_eq!(
        v.clauses_unchecked::<NoApp>(&token).unwrap_err().reason(),
        Reason::NonCanonical
    );
}

#[test]
fn leeway_is_capped_at_the_maximum() {
    // exp far in the past relative to `now`; a leeway beyond the 60s cap must
    // not resurrect it (the Limits and robustness rules, §16.10: leeway is bounded by a configured maximum).
    let token = issuer()
        .clauses(&NoApp::default())
        .exp(1_000)
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();

    // A wildly oversized leeway is clamped down — the token is still expired.
    let v = Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .leeway(Duration::from_secs(9_999_999_999));
    assert_eq!(
        v.clauses::<NoApp>(&token).unwrap_err().reason(),
        Reason::Expired
    );

    // Within the cap, leeway still works (exp 1000 + 60 > now 1030).
    let v = Verifier::new()
        .key(&key)
        .now(1_030)
        .leeway(Duration::from_secs(60));
    assert!(v.clauses::<NoApp>(&token).is_ok());

    // Just past the cap (exp 1000 + 60 <= now 1061) is rejected.
    let v = Verifier::new()
        .key(&key)
        .now(1_061)
        .leeway(Duration::from_secs(60));
    assert_eq!(
        v.clauses::<NoApp>(&token).unwrap_err().reason(),
        Reason::Expired
    );
}

#[test]
fn mint_rejects_non_uuidv7_tid() {
    // Wrong version (v4) is rejected at mint, not left for the verifier.
    let v4 = Uuid::parse_str("00000000-0000-4000-8000-000000000000").unwrap();
    let err = issuer()
        .clauses(&NoApp::default())
        .exp(4_000_000_000)
        .tid(v4)
        .mint()
        .unwrap_err();
    assert!(matches!(err, MintError::BadTid));

    // Version 7 but a non-RFC-4122 variant (NCS, nibble 0) is also rejected.
    let bad_variant = Uuid::parse_str("019ed29a-378d-72f0-0462-4929cd2bfcad").unwrap();
    let err = issuer()
        .clauses(&NoApp::default())
        .exp(4_000_000_000)
        .tid(bad_variant)
        .mint()
        .unwrap_err();
    assert!(matches!(err, MintError::BadTid));

    // A well-formed v7 tid still mints.
    let good = Uuid::parse_str("019ed29a-378d-72f0-b462-4929cd2bfcad").unwrap();
    assert!(issuer()
        .clauses(&NoApp::default())
        .exp(4_000_000_000)
        .tid(good)
        .mint()
        .is_ok());
}

#[test]
fn expires_in_saturates_instead_of_overflowing() {
    // A gigantic TTL must neither panic (debug) nor wrap to a past exp.
    let token = issuer()
        .clauses(&NoApp::default())
        .expires_in(Duration::from_secs(u64::MAX))
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    assert!(Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .clauses::<NoApp>(&token)
        .is_ok());
}

#[test]
fn rejects_oversize_mandate_half() {
    #[derive(Serialize, Deserialize, Debug)]
    struct Big {
        blob: String,
    }
    // App data large enough that the decoded half exceeds the 64 KiB default.
    let token = Issuer::new(MandateKey::from_bytes(KEY_BYTES).unwrap())
        .clauses(&Big {
            blob: "x".repeat(100 * 1024),
        })
        .exp(4_000_000_000)
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();

    // Default cap rejects it uniformly (before any trial decryption).
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.clauses::<Big>(&token).unwrap_err().reason(),
        Reason::Malformed
    );

    // A raised cap admits the same token.
    let v = Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .max_decoded_len(1024 * 1024);
    assert!(v.clauses::<Big>(&token).is_ok());
}

#[test]
fn mandate_only_token_has_no_manifest() {
    let token = issuer()
        .clauses(&NoApp::default())
        .exp(4_000_000_000)
        .mint()
        .unwrap();
    assert!(token.starts_with('.')); // no manifest half
    assert!(claims::<NoApp>(&token).is_none());
    // No standalone manifest half, but the mandate half carves out and
    // re-verifies on its own.
    assert!(obsigil::manifest(&token).is_none());
    let forwarded = obsigil::mandate(&token).expect("has a mandate half");
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    assert!(Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .clauses::<NoApp>(&forwarded)
        .is_ok());
}

#[test]
fn mandate_key_rejects_the_manifest_key() {
    assert!(MandateKey::from_bytes(obsigil::MANIFEST_KEY).is_err());
}
