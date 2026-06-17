//! Serialization dispatch (spec §7). Every registered format is pure data
//! — no decoder that can execute code or construct arbitrary host objects.
//! A half's plaintext is `tag(1 byte) || serialized-fields`.

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::MintError;
use crate::types::Format;

/// Serialize `value` to a half plaintext: the format's 1-byte tag followed
/// by the serialized fields (spec §7). Errors if the format is not built in.
pub fn to_plaintext<T: Serialize>(value: &T, format: Format) -> Result<Vec<u8>, MintError> {
    // Seed with the 1-byte format tag plus headroom for typical claims, so
    // the serializer doesn't repeatedly re-grow a zero-capacity buffer.
    let mut out = Vec::with_capacity(64);
    out.push(format.tag());
    match format {
        #[cfg(feature = "json")]
        Format::Json => {
            serde_json::to_writer(&mut out, value)
                .map_err(|e| MintError::Serialization(e.to_string()))?;
        }
        #[cfg(feature = "toml")]
        Format::Toml => {
            let s = toml::to_string(value).map_err(|e| MintError::Serialization(e.to_string()))?;
            out.extend_from_slice(s.as_bytes());
        }
        #[cfg(feature = "cbor")]
        Format::Cbor => {
            ciborium::into_writer(value, &mut out)
                .map_err(|e| MintError::Serialization(e.to_string()))?;
        }
        #[allow(unreachable_patterns)]
        other => return Err(MintError::UnsupportedFormat(other)),
    }
    Ok(out)
}

/// Deserialize the serialized-fields portion of a half plaintext, dispatched
/// on its 1-byte tag. `None` on an unknown/unbuilt tag or malformed bytes.
pub fn from_fields<T: DeserializeOwned>(tag: u8, fields: &[u8]) -> Option<T> {
    let format = Format::from_tag(tag)?;
    match format {
        #[cfg(feature = "json")]
        Format::Json => serde_json::from_slice(fields).ok(),
        #[cfg(feature = "toml")]
        Format::Toml => core::str::from_utf8(fields)
            .ok()
            .and_then(|s| toml::from_str(s).ok()),
        #[cfg(feature = "cbor")]
        Format::Cbor => ciborium::from_reader(fields).ok(),
        #[allow(unreachable_patterns)]
        _ => None,
    }
}
