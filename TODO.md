# obsigil-rs — TODO

The authoritative format is the obsigil spec:
`../spec/tex/spec.tex` (normative LaTeX source of truth), with
design reasoning in `../spec/RATIONALE.md`.

## Done since the scaffold

These were deferred during the initial scaffold and are now
implemented — do **not** redo. (The API moved from a flat
`encode`/`decode` shape to the `Issuer` / `MintBuilder` /
`Verifier` / `open_manifest` surface in `src/`.)

- **Reserved-field enforcement** (spec §11), on the mandate
  path only — manifest claims stay advisory. A present mandate
  MUST carry `exp` (rejected once `now >= exp`, configurable
  leeway, injectable `now`) and a UUIDv7 `tid`; a present `aud`
  is checked for membership against the verifier's identifier
  in constant time; a present manifest MUST carry `iss`
  (`open_manifest` returns `None` otherwise). See `verify.rs`.
- **Uniform opaque failure** (spec §9.5). Every rejection
  collapses to one `Error` whose `Display` is constant; the
  granular `Reason` is internal-only, via `Error::reason()` for
  logging/telemetry. See `error.rs`.
- **Token grammar** — exactly one separator, either half
  optional; the `.{mandate}` forward form is accepted. See
  `token.rs`.
- **Multi-key trial decryption** (spec §9.4) — `Verifier` tries
  each candidate key and accepts the first that authenticates;
  wrong key fails closed. See `verify.rs`.
- **`b64`/`hex` text encodings + separator mapping** (spec §3) —
  `.` => b64, `~` => hex, token-wide. See `encoding.rs`,
  `types.rs`.
- **Shared test vectors** — cross-implementation conformance
  against the sibling `obsigil-test-vectors` (positive
  bidirectional reproduction + negative cases). See
  `tests/conformance.rs`.
- **Packaging: version** — `0.1.0` for the first release.

## Open

- **`repository` field.** Set in `Cargo.toml` once a public
  obsigil namespace exists (kept out for now per the uvar
  privacy rule). This is the remaining blocker for a crates.io
  publish.
- **Model the companion secret.** The spec seals "a secret plus
  the optional mandate"; only the mandate clauses are modeled so
  far. Re-check against the spec whether anything is still owed
  now that sealing is direct-on-RustCrypto rather than via
  oboron's a-tier.
- **kaiv encoding.** Add a `k` tag once the kaiv format
  stabilizes (the spec reserves it).

## Non-goals

- **`p` (Perl hashref) and `y` (YAML) — excluded from the spec.**
  The spec's encoding rule is *capability-based*: a tag MUST NOT
  name a serialization whose decoder *can* execute code or
  construct arbitrary objects, because the keyless manifest is
  attacker-forgeable. `p` (`eval`-ed Perl source) and `y` (YAML —
  full-schema loaders construct arbitrary objects, the
  `yaml.load` / `Psych` RCE class) both fail that test, so
  neither is reserved — gone, not deferred. Allowed serializations
  are `j` (JSON), `t` (TOML), `c` (CBOR) — distinct from the text
  encoding (`b64`/`hex`), which the separator carries. (See the
  `Encoding` enum doc, the spec's *Serialization* section, and
  `../spec/RATIONALE.md` for the full reasoning.)
