//! Cross-implementation conformance against the language-agnostic
//! `obsigil-test-vectors` (spec §10). Runs only with the features needed to
//! cover every vector; enable with `--all-features` (or
//! `--features conformance,gcm-siv,toml,cbor`).
//!
//! The vectors live in the sibling `obsigil-test-vectors` repo; point at a
//! checkout with `OBSIGIL_TEST_VECTORS`, else the sibling path is used. If
//! neither is present the tests skip rather than fail.

#![cfg(all(
    feature = "conformance",
    feature = "gcm-siv",
    feature = "toml",
    feature = "cbor"
))]

use std::path::{Path, PathBuf};

use obsigil::lowlevel::{self, Alg, Encoding, MANIFEST_KEY};
use obsigil::{open_manifest, MandateKey, Verifier};
use serde_json::Value;

/// The published test mandate key (see the vectors' README).
const MANDATE_TEST_KEY_HEX: &str =
    "a341adc813cfa493412cda5900fa4ec83f20a6cdea4fe5c759f7ccdb7ffbec51\
e01d2ce90c592909adb2ac1cad771790353f439ac86e9b113a17f7c57f0684b0";

fn vectors_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("OBSIGIL_TEST_VECTORS") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../obsigil-test-vectors");
    sibling.is_dir().then_some(sibling)
}

fn read_vectors(dir: &Path, name: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(dir.join(name)).expect("read vectors file");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("parse vector line"))
        .collect()
}

fn key_for(role: &str) -> [u8; 64] {
    let hex = match role {
        "manifest" => return MANIFEST_KEY,
        "mandate" => MANDATE_TEST_KEY_HEX,
        other => other,
    };
    lowlevel::decode(hex, Encoding::Hex)
        .expect("key hex")
        .try_into()
        .expect("64-byte key")
}

fn encoding_of(s: &str) -> Encoding {
    match s {
        "b64" => Encoding::B64,
        "hex" => Encoding::Hex,
        other => panic!("unknown encoding {other}"),
    }
}

fn alg_of(s: &str) -> Alg {
    Alg::from_code(s.chars().next().unwrap()).expect("registered alg")
}

#[test]
fn positives_reproduce_bidirectionally() {
    let Some(dir) = vectors_dir() else {
        eprintln!("obsigil-test-vectors not found; skipping conformance");
        return;
    };
    let vectors = read_vectors(&dir, "test-vectors.jsonl");
    assert!(!vectors.is_empty(), "no positive vectors");

    for v in &vectors {
        let encoding = encoding_of(v["encoding"].as_str().unwrap());
        let mut left = String::new();
        let mut right = String::new();

        for role in ["manifest", "mandate"] {
            let Some(half) = v.get(role).filter(|h| !h.is_null()) else {
                continue;
            };
            let alg_str = half["alg"].as_str().unwrap();
            let alg = alg_of(alg_str);
            let key = key_for(role);
            let octets = lowlevel::decode(half["octets"].as_str().unwrap(), Encoding::Hex).unwrap();

            // seal direction: octets -> sealed -> encoded text.
            let text = lowlevel::encode(&lowlevel::seal(&octets, &key, alg).unwrap(), encoding);
            // open direction: text -> decoded -> octets.
            let reopened =
                lowlevel::open(&lowlevel::decode(&text, encoding).unwrap(), &key, alg).unwrap();
            assert_eq!(reopened, octets, "open != octets for {role}");

            if role == "manifest" {
                left = format!("{text}{alg_str}");
            } else {
                right = format!("{alg_str}{text}");
            }
        }

        let sep = encoding.separator();
        assert_eq!(
            format!("{left}{sep}{right}"),
            v["token"].as_str().unwrap(),
            "assembled token mismatch"
        );
    }
}

#[test]
fn negatives_are_rejected() {
    let Some(dir) = vectors_dir() else {
        eprintln!("obsigil-test-vectors not found; skipping conformance");
        return;
    };
    let vectors = read_vectors(&dir, "negative-test-vectors.jsonl");
    assert!(!vectors.is_empty(), "no negative vectors");

    for v in &vectors {
        let op = v["op"].as_str().unwrap();
        let token = v["token"].as_str().unwrap();
        let rejected = match op {
            "parse" => lowlevel::parse(token).is_none(),
            "open-manifest" => open_manifest::<Value>(token).is_none(),
            "verify" => {
                let key = key_for(v.get("key").and_then(|k| k.as_str()).unwrap_or("mandate"));
                let mk = MandateKey::from_bytes(key).expect("vector mandate key");
                let mut ver = Verifier::new().key(&mk);
                if let Some(now) = v.get("now").and_then(Value::as_i64) {
                    ver = ver.now(now);
                }
                if let Some(aud) = v.get("audience").and_then(Value::as_str) {
                    ver = ver.audience(aud);
                }
                ver.verify::<Value>(token).is_err()
            }
            other => panic!("unknown op {other}"),
        };
        assert!(
            rejected,
            "should reject ({}): {token}",
            v["reason"].as_str().unwrap_or("")
        );
    }
}
