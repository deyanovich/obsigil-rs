# obsigil-rs — TODO

The authoritative format is the obsigil spec:
`../spec/tex/spec.tex` (normative LaTeX source of truth), with
design reasoning in `../spec/RATIONALE.md`.

## Done since the scaffold

These were deferred during the initial scaffold and are now
implemented — do **not** redo. (The API moved from a flat
`encode`/`decode` shape to the `Issuer` / `MintBuilder` /
`Verifier` / `open_manifest` surface in `src/`.)

- **Reserved-field enforcement** (the Reserved fields section, §8), on the mandate
  path only — manifest claims stay advisory. A present mandate
  MUST carry `exp` (rejected once `now >= exp`, configurable
  leeway, injectable `now`) and a UUIDv7 `tid`; a present `aud`
  is checked for membership against the verifier's identifier
  in constant time; a present manifest MUST carry `iss`
  (`open_manifest` returns `None` otherwise). See `verify.rs`.
- **Uniform opaque failure** (the uniform-failure rule of the Security Considerations, §16.6). Every rejection
  collapses to one `Error` whose `Display` is constant; the
  granular `Reason` is internal-only, via `Error::reason()` for
  logging/telemetry. See `error.rs`.
- **Token grammar** — exactly one separator, either half
  optional; the `.{mandate}` forward form is accepted. See
  `token.rs`.
- **Multi-key trial decryption** (the trial-decryption key selection of the Security Considerations, §16.5) — `Verifier` tries
  each candidate key and accepts the first that authenticates;
  wrong key fails closed. See `verify.rs`.
- **`b64`/`hex` text encodings + separator mapping** (the Token structure section, §4) —
  `.` => b64, `~` => hex, token-wide. See `encoding.rs`,
  `types.rs`.
- **Shared test vectors** — cross-implementation conformance
  against the sibling `obsigil-test-vectors` (positive
  bidirectional reproduction + negative cases). See
  `tests/conformance.rs`.
- **Packaging: version** — `0.2.0` for the canonical-CBOR
  model (a breaking change from the `0.1.x` per-half
  JSON/TOML/CBOR serialization).
- **`repository` field — set.** Both `Cargo.toml` manifests
  point at the public namespace
  (`https://gitlab.com/obsigil/obsigil-rs`), clearing the last
  crates.io-publish blocker.
- **Canonical-CBOR serialization** (the Serialization rules, §7). Both halves are a
  fixed canonical CBOR map; reserved fields at negative integer
  keys (`tid` −1 … `iss` −5), obsigil-owned encoding, strict
  rejection of non-canonical input, and the sign-split
  namespace (unknown negative key fails closed). See
  `serial.rs`.

## Open

- **Model the companion secret.** The spec seals "a secret plus
  the optional mandate"; only the mandate clauses are modeled so
  far. Re-check against the spec whether anything is still owed
  now that sealing is direct-on-RustCrypto rather than via
  oboron's a-tier.
## Non-goals

- **Per-half serialization choice (`j`/`t`/`c`) and the `p`/`y`
  exclusions — gone in `0.2`.** The model fixes one
  serialization (canonical CBOR), so there is no tag registry
  and no per-format capability rule to police: obsigil only
  ever CBOR-decodes, a pure data format, so the
  forged-manifest-RCE vector the old rule guarded against (Perl
  `eval`, YAML full-load) is foreclosed by construction. An
  application that needs a foreign serialization carries it in
  an opaque byte-string field and owns its own decoder. (See
  the spec's *Serialization* section and `../spec/RATIONALE.md`.)
