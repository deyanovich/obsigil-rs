CHANGELOG
=========

All notable changes to obsigil (the `obsigil` library and
`obsigil-cli`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
but note that pre-1.0 releases may not adhere strictly to all
guidelines. Releases before 0.4.0 predate this changelog; see the
`lib/v*` and `cli/v*` git tags.


[Unreleased]
------------


[0.4.0] - 2026-07-01
--------------------

Hex is now the default key representation, aligning with the spec's
Key format (§6.2) and the sibling oboron crate. No wire-format change:
keys never appear on the wire, so existing tokens are unaffected.

### Breaking

- `generate_key()` now returns a `String` — a fresh key as 128
  lowercase hex digits, the form to store as a secret (an environment
  variable) — instead of a `MandateKey`. For an in-memory opaque key,
  use `MandateKey::generate()`.
- **CLI:** `--key` is canonical lowercase hex; an uppercase key is now
  rejected rather than silently lowercased.

### Added

- `MandateKey::from_hex(&str)` — construct a mandate key from its
  canonical hex string (the default input form); `from_bytes([u8; 64])`
  remains the raw-octet alternative.
- `KeyError::BadHexEncoding` and `KeyError::BadHexLength` — a malformed
  hex key surfaces as a distinct, descriptive configuration error,
  never the verifier's opaque uniform failure.

### Changed

- **CLI:** `generate-key` now emits the library's hex key; dropped the
  unused `getrandom` dependency.
