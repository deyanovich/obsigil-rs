//! Integration tests over the public API (spec §10): a positive round-trip
//! and the required negative cases.

use obsigil::{
    open_manifest, Issuer, Mandate, MandateKey, Manifest, NoApp, Reason, Uuid, Verifier,
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

#[test]
fn rejects_non_uuidv7_tid() {
    let token = issuer()
        .mandate(&NoApp::default())
        .exp(4_000_000_000)
        .tid(Uuid::from_u128(0)) // nil UUID, version 0
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let v = Verifier::new().key(&key).now(1_000_000_000);
    assert_eq!(
        v.verify::<NoApp>(&token).unwrap_err().reason(),
        Reason::BadTid
    );
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

#[cfg(feature = "cbor")]
#[test]
fn cbor_mandate_round_trips() {
    // CBOR carries `tid` as 16-byte binary (spec §11.3); it must still
    // validate as a UUIDv7 and round-trip the flattened app data.
    let token = Issuer::new(MandateKey::from_bytes(KEY_BYTES).unwrap())
        .format(obsigil::Format::Cbor)
        .mandate(&Access {
            role: "admin".into(),
        })
        .exp(4_000_000_000)
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let mandate: Mandate<Access> = Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .verify(&token)
        .unwrap();
    assert_eq!(mandate.app().role, "admin");
    assert_eq!(mandate.tid().get_version_num(), 7);
}

#[cfg(feature = "toml")]
#[test]
fn toml_mandate_round_trips() {
    let token = Issuer::new(MandateKey::from_bytes(KEY_BYTES).unwrap())
        .format(obsigil::Format::Toml)
        .mandate(&Access {
            role: "admin".into(),
        })
        .exp(4_000_000_000)
        .mint()
        .unwrap();
    let key = MandateKey::from_bytes(KEY_BYTES).unwrap();
    let mandate: Mandate<Access> = Verifier::new()
        .key(&key)
        .now(1_000_000_000)
        .verify(&token)
        .unwrap();
    assert_eq!(mandate.app().role, "admin");
}
