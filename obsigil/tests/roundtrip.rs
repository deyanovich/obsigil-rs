//! Integration tests over the public API (spec §10): a positive round-trip
//! and the required negative cases.

use std::time::Duration;

use obsigil::{
    open_manifest, Issuer, Mandate, MandateKey, Manifest, MintError, NoApp, Reason, Uuid, Verifier,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Access {
    role: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Display {
    theme: String,
}

const KEY_BYTES: [u8; 64] = [42u8; 64];

fn issuer() -> Issuer {
    Issuer::new(MandateKey::from_bytes(KEY_BYTES).unwrap())
}

fn full_token() -> String {
    issuer()
        .mandate(&Access {
            role: "admin".into(),
        })
        .exp(4_000_000_000)
        .audience(["api"])
        .subject("u42")
        .manifest(
            "auth.example",
            &Display {
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
    let manifest: Manifest<Display> = open_manifest(&token).unwrap();
    assert_eq!(manifest.issuer(), "auth.example");
    assert_eq!(manifest.app().theme, "dark");

    // Backend verification (authoritative).
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let verifier = Verifier::new().key(&key).audience("api").now(1_000_000_000);
    let mandate: Mandate<Access> = verifier.verify(&token).unwrap();
    assert_eq!(mandate.app().role, "admin");
    assert_eq!(mandate.subject(), Some("u42"));
    assert_eq!(mandate.exp(), 4_000_000_000);
    assert_eq!(mandate.tid().get_version_num(), 7);
}

#[test]
fn verifies_the_forwarded_mandate_only_form() {
    let token = full_token();
    let sep = token.find(['.', '~']).unwrap();
    let forwarded = &token[sep..]; // ".0<mandate>" — the §8 forward form
    assert!(forwarded.starts_with('.'));

    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let verifier = Verifier::new().key(&key).audience("api").now(1_000_000_000);
    assert!(verifier.verify::<Access>(forwarded).is_ok());
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
    assert!(verifier.verify::<Access>(&token).is_ok());
}

#[test]
fn rejects_uniformly_with_internal_reasons() {
    let token = full_token();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let wrong = MandateKey::from_bytes([7u8; 64]).unwrap();

    // expired
    let v = Verifier::new().key(&key).audience("api").now(4_000_000_001);
    let e = v.verify::<Access>(&token).unwrap_err();
    assert_eq!(e.reason(), Reason::Expired);
    assert_eq!(e.to_string(), "obsigil: token rejected"); // uniform Display

    // aud mismatch (wrong audience)
    let v = Verifier::new()
        .key(&key)
        .audience("other")
        .now(1_000_000_000);
    assert_eq!(
        v.verify::<Access>(&token).unwrap_err().reason(),
        Reason::AudienceMismatch
    );

    // aud present but verifier has none
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.verify::<Access>(&token).unwrap_err().reason(),
        Reason::AudienceMismatch
    );

    // wrong key
    let v = Verifier::new()
        .key(&wrong)
        .audience("api")
        .now(1_000_000_000);
    assert_eq!(
        v.verify::<Access>(&token).unwrap_err().reason(),
        Reason::AuthFailed
    );

    // malformed
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.verify::<Access>("garbage").unwrap_err().reason(),
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
        let token = craft(vec![(ik(-1), tid_bytes(tid)), (ik(-2), exp_val(4_000_000_000))]);
        Verifier::new()
            .key(&key)
            .now(1_000_000_000)
            .verify::<NoApp>(&token)
            .unwrap_err()
            .reason()
    };
    // Wrong version (nil UUID, version 0).
    assert_eq!(reason("00000000-0000-0000-0000-000000000000"), Reason::BadTid);
    // Version 7 but a non-RFC-4122 variant (NCS, nibble 0) — spec §12.3.
    assert_eq!(reason("019ed29a-378d-72f0-0462-4929cd2bfcad"), Reason::BadTid);
    // A well-formed v7 tid verifies.
    let good = craft(vec![
        (ik(-1), tid_bytes("019ed29a-378d-72f0-b462-4929cd2bfcad")),
        (ik(-2), exp_val(4_000_000_000)),
    ]);
    assert!(Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .verify::<NoApp>(&good)
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
            .verify::<NoApp>(&craft(entries))
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
        reason(vec![(ik(-2), exp_val(4_000_000_000)), (ik(-1), tid_bytes(tid))]),
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

#[test]
fn leeway_is_capped_at_the_maximum() {
    // exp far in the past relative to `now`; a leeway beyond the 60s cap must
    // not resurrect it (spec §9.9: leeway is bounded by a configured maximum).
    let token = issuer()
        .mandate(&NoApp::default())
        .exp(1_000)
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();

    // A wildly oversized leeway is clamped down — the token is still expired.
    let v = Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .leeway(Duration::from_secs(9_999_999_999));
    assert_eq!(v.verify::<NoApp>(&token).unwrap_err().reason(), Reason::Expired);

    // Within the cap, leeway still works (exp 1000 + 60 > now 1030).
    let v = Verifier::new()
        .key(&key)
        .now(1_030)
        .leeway(Duration::from_secs(60));
    assert!(v.verify::<NoApp>(&token).is_ok());

    // Just past the cap (exp 1000 + 60 <= now 1061) is rejected.
    let v = Verifier::new()
        .key(&key)
        .now(1_061)
        .leeway(Duration::from_secs(60));
    assert_eq!(v.verify::<NoApp>(&token).unwrap_err().reason(), Reason::Expired);
}

#[test]
fn mint_rejects_non_uuidv7_tid() {
    // Wrong version (v4) is rejected at mint, not left for the verifier.
    let v4 = Uuid::parse_str("00000000-0000-4000-8000-000000000000").unwrap();
    let err = issuer()
        .mandate(&NoApp::default())
        .exp(4_000_000_000)
        .tid(v4)
        .mint()
        .unwrap_err();
    assert!(matches!(err, MintError::BadTid));

    // Version 7 but a non-RFC-4122 variant (NCS, nibble 0) is also rejected.
    let bad_variant = Uuid::parse_str("019ed29a-378d-72f0-0462-4929cd2bfcad").unwrap();
    let err = issuer()
        .mandate(&NoApp::default())
        .exp(4_000_000_000)
        .tid(bad_variant)
        .mint()
        .unwrap_err();
    assert!(matches!(err, MintError::BadTid));

    // A well-formed v7 tid still mints.
    let good = Uuid::parse_str("019ed29a-378d-72f0-b462-4929cd2bfcad").unwrap();
    assert!(issuer()
        .mandate(&NoApp::default())
        .exp(4_000_000_000)
        .tid(good)
        .mint()
        .is_ok());
}

#[test]
fn expires_in_saturates_instead_of_overflowing() {
    // A gigantic TTL must neither panic (debug) nor wrap to a past exp.
    let token = issuer()
        .mandate(&NoApp::default())
        .expires_in(Duration::from_secs(u64::MAX))
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    assert!(Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .verify::<NoApp>(&token)
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
        .mandate(&Big {
            blob: "x".repeat(100 * 1024),
        })
        .exp(4_000_000_000)
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();

    // Default cap rejects it uniformly (before any trial decryption).
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(v.verify::<Big>(&token).unwrap_err().reason(), Reason::Malformed);

    // A raised cap admits the same token.
    let v = Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .max_decoded_len(1024 * 1024);
    assert!(v.verify::<Big>(&token).is_ok());
}

#[test]
fn mandate_only_token_has_no_manifest() {
    let token = issuer()
        .mandate(&NoApp::default())
        .exp(4_000_000_000)
        .mint()
        .unwrap();
    assert!(token.starts_with('.')); // no manifest half
    assert!(open_manifest::<NoApp>(&token).is_none());
}

#[test]
fn mandate_key_rejects_the_manifest_key() {
    assert!(MandateKey::from_bytes(obsigil::MANIFEST_KEY).is_err());
}
