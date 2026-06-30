//! Canonical CBOR serialization (the Serialization rules, §7). Both halves are a single
//! canonical CBOR map (RFC 8949 §4.2): definite-length items, shortest-form
//! integers and lengths, and map keys sorted by their encoded bytes.
//! obsigil *owns* the encoding — given field *values*, it emits the canonical
//! bytes itself, so identical fields mint byte-identical tokens.
//!
//! Field keys split by sign. Reserved fields take negative integer keys (the
//! protocol's namespace — the entire negative space); application data takes
//! non-negative integers and text strings. The sign *is* the namespace, read
//! from the CBOR major type. A verifier rejects a half that is not canonical
//! CBOR, that repeats a key, or that carries an unrecognized negative key
//! (fail closed), and ignores an unrecognized non-negative or text-string
//! key (opaque application data).

use std::collections::HashSet;

use ciborium::value::{Integer, Value};
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{MintError, Reason};
use crate::reserved::{MandateFields, ManifestFields};
use crate::types::NumericDate;

// Reserved field keys (the Reserved fields section, §8): negative integers, single-byte through -24.
const KEY_TID: i8 = -1;
const KEY_EXP: i8 = -2;
const KEY_AUD: i8 = -3;
const KEY_SUB: i8 = -4;
const KEY_ISS: i8 = -5;

const RESERVED: [i8; 5] = [KEY_TID, KEY_EXP, KEY_AUD, KEY_SUB, KEY_ISS];

#[inline]
fn ikey(n: i8) -> Value {
    Value::Integer(Integer::from(n))
}

/// Encode one CBOR value to bytes. ciborium emits shortest-form integers and
/// definite lengths; canonical key ordering is layered on by [`canonicalize`].
/// Writing to a `Vec` is infallible.
fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encode to Vec is infallible");
    out
}

/// Put a value into canonical form in place: sort every map's entries by the
/// bytewise order of each key's encoded CBOR (RFC 8949 §4.2.1), depth-first so
/// nested maps are canonical too.
fn canonicalize(value: &mut Value) {
    match value {
        Value::Map(entries) => {
            for (k, v) in entries.iter_mut() {
                canonicalize(k);
                canonicalize(v);
            }
            entries.sort_by_cached_key(|(k, _)| encode(k));
        }
        Value::Array(items) => items.iter_mut().for_each(canonicalize),
        Value::Tag(_, inner) => canonicalize(inner.as_mut()),
        // Scalars need no ordering. ciborium emits shortest-form floats by
        // default — the smallest of f16/f32/f64 that round-trips the value,
        // per RFC 8949 §4.2 — so a float application value canonicalizes
        // through encode/decode; the reserved fields, the security-relevant
        // part, are integers, byte strings, text, and arrays of text, all
        // fully canonicalized above.
        _ => {}
    }
}

/// True iff `k` is a CBOR negative integer (major type 1), read from the
/// encoded key's leading byte — the sign that marks obsigil's namespace.
fn is_negative_int(k: &Value) -> bool {
    matches!(k, Value::Integer(_)) && encode(k).first().is_some_and(|b| b >> 5 == 1)
}

/// True iff `value` carries a floating-point `NaN` anywhere. `NaN` has no
/// single canonical CBOR bit pattern across encoders, so obsigil forbids it
/// (the Serialization rules, §7): mint refuses to emit one and a verifier rejects a half with one.
fn contains_nan(value: &Value) -> bool {
    match value {
        Value::Float(f) => f.is_nan(),
        Value::Array(items) => items.iter().any(contains_nan),
        Value::Map(entries) => entries.iter().any(|(k, v)| contains_nan(k) || contains_nan(v)),
        Value::Tag(_, inner) => contains_nan(inner),
        _ => false,
    }
}

/// True iff `value` contains a CBOR map — at the top level or nested at any
/// depth inside an application value — whose key is neither a CBOR integer
/// nor a text string (the Serialization rules, §7). Such a key has no portable representation —
/// Go cannot key a map by a byte slice — so obsigil forbids a non-integer,
/// non-text key at *every* map depth, not only the half's top-level map. A
/// verifier rejects a half with one rather than accept a token no conformant
/// implementation could decode.
fn has_invalid_map_key(value: &Value) -> bool {
    match value {
        Value::Map(entries) => entries.iter().any(|(k, v)| {
            !matches!(k, Value::Integer(_) | Value::Text(_)) || has_invalid_map_key(v)
        }),
        Value::Array(items) => items.iter().any(has_invalid_map_key),
        Value::Tag(_, inner) => has_invalid_map_key(inner),
        _ => false,
    }
}

/// Classify a decoded map key: which reserved field it is (if any), or whether
/// it is an application key (non-negative integer / text string), an unknown
/// reserved (negative) key, or an invalid key type.
enum KeyKind {
    Reserved(i8),
    UnknownReserved,
    App,
    Invalid,
}

fn classify(k: &Value) -> KeyKind {
    for n in RESERVED {
        if k == &ikey(n) {
            return KeyKind::Reserved(n);
        }
    }
    if is_negative_int(k) {
        KeyKind::UnknownReserved
    } else if matches!(k, Value::Integer(_) | Value::Text(_)) {
        KeyKind::App
    } else {
        KeyKind::Invalid
    }
}

// --- minting (field values -> canonical CBOR plaintext) --------------------

/// Serialize the application value to a CBOR map's entries. Errors if it does
/// not serialize to a map, or if it intrudes on the reserved namespace with a
/// negative integer key (the Serialization rules, §7).
fn app_entries<T: Serialize>(app: &T) -> Result<Vec<(Value, Value)>, MintError> {
    let value = Value::serialized(app).map_err(|e| MintError::Serialization(e.to_string()))?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(MintError::AppNotMap),
    };
    if entries.iter().any(|(k, _)| is_negative_int(k)) {
        return Err(MintError::ReservedKey);
    }
    if entries.iter().any(|(_, v)| contains_nan(v)) {
        return Err(MintError::Nan);
    }
    Ok(entries)
}

/// Canonically encode an assembled set of map entries to a half plaintext.
fn assemble(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut value = Value::Map(entries);
    canonicalize(&mut value);
    encode(&value)
}

/// Build a mandate's canonical-CBOR plaintext from its reserved clauses and
/// application value (the Serialization rules, §7; the Reserved fields section, §8). `tid` is encoded as its 16-byte binary
/// form (the `tid` field, §8.2).
pub(crate) fn to_mandate_plaintext<T: Serialize>(
    exp: NumericDate,
    tid: Uuid,
    iss: Option<&str>,
    aud: Option<&[String]>,
    sub: Option<&str>,
    app: &T,
) -> Result<Vec<u8>, MintError> {
    let mut entries = app_entries(app)?;
    entries.push((ikey(KEY_TID), Value::Bytes(tid.as_bytes().to_vec())));
    entries.push((ikey(KEY_EXP), Value::Integer(Integer::from(exp))));
    if let Some(aud) = aud {
        let arr = aud.iter().map(|s| Value::Text(s.clone())).collect();
        entries.push((ikey(KEY_AUD), Value::Array(arr)));
    }
    if let Some(sub) = sub {
        entries.push((ikey(KEY_SUB), Value::Text(sub.to_owned())));
    }
    if let Some(iss) = iss {
        entries.push((ikey(KEY_ISS), Value::Text(iss.to_owned())));
    }
    Ok(assemble(entries))
}

/// Build a manifest's canonical-CBOR plaintext: the required `iss` claim and
/// the application claims (the Serialization rules, §7; the `iss` field, §8.6).
pub(crate) fn to_manifest_plaintext<T: Serialize>(
    iss: &str,
    app: &T,
) -> Result<Vec<u8>, MintError> {
    let mut entries = app_entries(app)?;
    entries.push((ikey(KEY_ISS), Value::Text(iss.to_owned())));
    Ok(assemble(entries))
}

// --- verifying (canonical CBOR plaintext -> field values) ------------------

/// Strictly decode a half plaintext to its map entries, rejecting any
/// non-canonical encoding (the Serialization rules, §7; the Limits and robustness rules of the Security Considerations, §16.10): a top-level non-map, a duplicate
/// map key, or — caught by re-encoding canonically and comparing — unsorted
/// keys, non-shortest integers/lengths, indefinite-length items, or trailing
/// bytes after the map.
fn strict_map(plain: &[u8]) -> Result<Vec<(Value, Value)>, Reason> {
    let value: Value = ciborium::from_reader(plain).map_err(|_| Reason::Malformed)?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(Reason::Malformed),
    };
    // NaN has no canonical bit pattern across encoders, so obsigil forbids it
    // (the Serialization rules, §7). ciborium would otherwise accept the canonical quiet NaN.
    if entries.iter().any(|(k, v)| contains_nan(k) || contains_nan(v)) {
        return Err(Reason::NonCanonical);
    }
    // A CBOR map key that is not an integer or text string has no portable
    // representation (Go cannot key a map by a byte slice), so obsigil forbids
    // such a key at *every* map depth — not only this top-level map, but any
    // map nested inside an application value (the Serialization rules, §7). Top-level keys are also
    // classified per-field below; this recursion additionally reaches nested
    // maps, which `classify` never sees.
    if entries
        .iter()
        .any(|(k, v)| !matches!(k, Value::Integer(_) | Value::Text(_)) || has_invalid_map_key(v))
    {
        return Err(Reason::NonCanonical);
    }
    // Canonical CBOR forbids duplicate keys.
    let mut seen = HashSet::with_capacity(entries.len());
    for (k, _) in &entries {
        if !seen.insert(encode(k)) {
            return Err(Reason::NonCanonical);
        }
    }
    // Re-encode canonically and compare: catches unsorted keys, non-shortest
    // integers/lengths, indefinite-length items, and trailing bytes at once.
    let mut canon = Value::Map(entries.clone());
    canonicalize(&mut canon);
    if encode(&canon) != plain {
        return Err(Reason::NonCanonical);
    }
    Ok(entries)
}

fn read_tid(v: &Value) -> Result<Uuid, Reason> {
    match v {
        Value::Bytes(b) if b.len() == 16 => {
            Ok(Uuid::from_bytes(b[..16].try_into().expect("len checked")))
        }
        _ => Err(Reason::BadType),
    }
}

fn read_int(v: &Value) -> Result<NumericDate, Reason> {
    match v {
        Value::Integer(i) => NumericDate::try_from(*i).map_err(|_| Reason::BadType),
        _ => Err(Reason::BadType),
    }
}

fn read_text(v: &Value) -> Result<String, Reason> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(Reason::BadType),
    }
}

fn read_aud(v: &Value) -> Result<Vec<String>, Reason> {
    match v {
        Value::Array(items) => items
            .iter()
            .map(|it| match it {
                Value::Text(s) => Ok(s.clone()),
                _ => Err(Reason::BadType),
            })
            .collect(),
        _ => Err(Reason::BadType),
    }
}

/// Reconstruct the application value from the non-reserved entries.
fn decode_app<T: DeserializeOwned>(entries: Vec<(Value, Value)>) -> Result<T, Reason> {
    Value::Map(entries)
        .deserialized::<T>()
        .map_err(|_| Reason::Malformed)
}

/// Decode a mandate's canonical-CBOR plaintext into its clauses (the Reserved fields section, §8).
/// Presence and value-range policy (`tid` UUIDv7 version/variant, `exp`
/// expiry, `aud` membership) is applied by the verifier; here we extract and
/// type-check the reserved fields and split off the application clauses.
pub(crate) fn from_mandate_plaintext<T: DeserializeOwned>(
    plain: &[u8],
) -> Result<MandateFields<T>, Reason> {
    let entries = strict_map(plain)?;
    let mut exp = None;
    let mut tid = None;
    let mut iss = None;
    let mut aud = None;
    let mut sub = None;
    let mut app = Vec::new();

    for (k, v) in entries {
        match classify(&k) {
            KeyKind::Reserved(KEY_TID) => tid = Some(read_tid(&v)?),
            KeyKind::Reserved(KEY_EXP) => exp = Some(read_int(&v)?),
            KeyKind::Reserved(KEY_AUD) => aud = Some(read_aud(&v)?),
            KeyKind::Reserved(KEY_SUB) => sub = Some(read_text(&v)?),
            KeyKind::Reserved(KEY_ISS) => iss = Some(read_text(&v)?),
            KeyKind::Reserved(_) => unreachable!("RESERVED covers every match arm"),
            KeyKind::UnknownReserved => return Err(Reason::UnknownReservedKey),
            KeyKind::App => app.push((k, v)),
            KeyKind::Invalid => return Err(Reason::NonCanonical),
        }
    }

    Ok(MandateFields {
        exp,
        tid,
        iss,
        aud,
        sub,
        app: decode_app(app)?,
    })
}

/// Decode a manifest's canonical-CBOR plaintext into its claims (the `iss` field, §8.6).
/// The manifest is advisory: any decode problem, a missing `iss`, or any
/// reserved key other than `iss`/`exp` yields `None` (open as nothing rather
/// than fail), never an oracle (the non-authoritative-manifest rule of the Security Considerations, §16.7).
pub(crate) fn from_manifest_plaintext<T: DeserializeOwned>(plain: &[u8]) -> Option<ManifestFields<T>> {
    let entries = strict_map(plain).ok()?;
    let mut iss = None;
    let mut exp = None;
    let mut app = Vec::new();

    for (k, v) in entries {
        match classify(&k) {
            KeyKind::Reserved(KEY_ISS) => iss = Some(read_text(&v).ok()?),
            KeyKind::Reserved(KEY_EXP) => exp = Some(read_int(&v).ok()?),
            // tid/aud/sub are not manifest claims, and an unknown negative key
            // is obsigil's namespace: either way, treat the manifest as
            // nothing to show.
            KeyKind::Reserved(_) | KeyKind::UnknownReserved | KeyKind::Invalid => return None,
            KeyKind::App => app.push((k, v)),
        }
    }

    Some(ManifestFields {
        iss: iss?,
        exp,
        app: Value::Map(app).deserialized::<T>().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, PartialEq, Debug, Default)]
    struct App {
        role: String,
        n: u32,
    }

    fn tid7() -> Uuid {
        Uuid::now_v7()
    }

    #[test]
    fn mandate_round_trips_reserved_and_app() {
        let tid = tid7();
        let pt = to_mandate_plaintext(
            1000,
            tid,
            Some("auth.example"),
            Some(&["api".to_string(), "admin".to_string()]),
            Some("user-1"),
            &App {
                role: "admin".into(),
                n: 7,
            },
        )
        .unwrap();
        let c: MandateFields<App> = from_mandate_plaintext(&pt).unwrap();
        assert_eq!(c.exp, Some(1000));
        assert_eq!(c.tid, Some(tid));
        assert_eq!(c.iss.as_deref(), Some("auth.example"));
        assert_eq!(c.aud.as_deref(), Some(&["api".to_string(), "admin".to_string()][..]));
        assert_eq!(c.sub.as_deref(), Some("user-1"));
        assert_eq!(c.app, App { role: "admin".into(), n: 7 });
    }

    #[test]
    fn encoding_is_canonical_and_deterministic() {
        // Same logical fields -> byte-identical plaintext.
        let tid = tid7();
        let a = to_mandate_plaintext(1, tid, None, None, None, &App { role: "x".into(), n: 1 }).unwrap();
        let b = to_mandate_plaintext(1, tid, None, None, None, &App { role: "x".into(), n: 1 }).unwrap();
        assert_eq!(a, b);
        // Keys are sorted: app non-negative/text keys precede the negative
        // reserved keys in canonical order (major type 0/3 before 1)? No — the
        // app text keys (major type 3, 0x60+) sort AFTER the negatives (0x20+),
        // and there are no non-negative int keys here, so order is: tid(-1),
        // exp(-2)... then text app keys. We just assert it re-validates.
        let c: MandateFields<App> = from_mandate_plaintext(&a).unwrap();
        assert_eq!(c.app, App { role: "x".into(), n: 1 });
    }

    #[test]
    fn rejects_non_canonical_unsorted_keys() {
        // Hand-build a map with reserved keys out of canonical order.
        let tid = tid7();
        let unsorted = Value::Map(vec![
            (ikey(KEY_EXP), Value::Integer(Integer::from(5))),
            (ikey(KEY_TID), Value::Bytes(tid.as_bytes().to_vec())),
        ]);
        let bytes = encode(&unsorted); // not key-sorted (-2 before -1)
        // -2 encodes 0x21, -1 encodes 0x20; canonical wants 0x20 first.
        assert_eq!(
            from_mandate_plaintext::<crate::reserved::NoApp>(&bytes).unwrap_err(),
            Reason::NonCanonical
        );
    }

    #[test]
    fn rejects_duplicate_key() {
        let dup = Value::Map(vec![
            (ikey(KEY_EXP), Value::Integer(Integer::from(1))),
            (ikey(KEY_EXP), Value::Integer(Integer::from(2))),
        ]);
        let bytes = encode(&dup);
        assert_eq!(
            from_mandate_plaintext::<crate::reserved::NoApp>(&bytes).unwrap_err(),
            Reason::NonCanonical
        );
    }

    #[test]
    fn unknown_negative_key_fails_closed() {
        let m = Value::Map(vec![(ikey(-9), Value::Integer(Integer::from(1)))]);
        let bytes = encode(&m);
        assert_eq!(
            from_mandate_plaintext::<crate::reserved::NoApp>(&bytes).unwrap_err(),
            Reason::UnknownReservedKey
        );
    }

    #[test]
    fn wrong_type_reserved_field_rejected() {
        // tid as text instead of 16-byte bytes.
        let m = Value::Map(vec![(ikey(KEY_TID), Value::Text("nope".into()))]);
        let bytes = encode(&m);
        assert_eq!(
            from_mandate_plaintext::<crate::reserved::NoApp>(&bytes).unwrap_err(),
            Reason::BadType
        );
    }

    #[test]
    fn rejects_nan_float() {
        // An application NaN float — even ciborium's canonical quiet NaN — has
        // no canonical bit pattern across encoders and is rejected (the Serialization rules, §7).
        let m = Value::Map(vec![(Value::Integer(Integer::from(0)), Value::Float(f64::NAN))]);
        let bytes = encode(&m);
        assert_eq!(
            from_mandate_plaintext::<crate::reserved::NoApp>(&bytes).unwrap_err(),
            Reason::NonCanonical
        );
        // Mint refuses to emit one, too.
        use std::collections::BTreeMap;
        let app = BTreeMap::from([("x".to_string(), f64::NAN)]);
        assert!(matches!(
            to_mandate_plaintext(1, tid7(), None, None, None, &app),
            Err(MintError::Nan)
        ));
    }

    #[test]
    fn app_reserved_key_rejected_on_mint() {
        use std::collections::BTreeMap;
        // An app map that uses a negative integer key intrudes on the reserved
        // (negative-integer) namespace -> ReservedKey. Integer-keyed serde maps
        // serialize to integer CBOR keys, so this arm is reachable.
        let app = BTreeMap::from([(-1i64, 5u32)]);
        assert!(matches!(
            to_manifest_plaintext("iss", &app),
            Err(MintError::ReservedKey)
        ));
        // The mandate path shares app_entries, so it rejects the same intrusion.
        assert!(matches!(
            to_mandate_plaintext(1, tid7(), None, None, None, &app),
            Err(MintError::ReservedKey)
        ));
    }

    #[test]
    fn app_not_map_rejected_on_mint() {
        // A value that does not serialize to a CBOR map -> AppNotMap.
        #[derive(Serialize)]
        struct Bad;
        assert!(matches!(
            to_manifest_plaintext("iss", &Bad),
            Err(MintError::AppNotMap)
        ));
    }

    #[test]
    fn manifest_round_trips() {
        let pt = to_manifest_plaintext("auth.example", &App { role: "ui".into(), n: 2 }).unwrap();
        let c: ManifestFields<App> = from_manifest_plaintext(&pt).unwrap();
        assert_eq!(c.iss, "auth.example");
        assert_eq!(c.app, App { role: "ui".into(), n: 2 });
    }
}
