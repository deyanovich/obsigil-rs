# obsigil-cli

Command-line tool for the **obsigil** mandate-token format — a
shared-secret JWT alternative. Installs an `obsigil` binary.

## Install

```sh
cargo install obsigil-cli
```

## Commands

High-level:

- `mint` — mint a token from clauses (and an optional manifest)
- `verify` — verify a token's mandate; prints the clauses as JSON,
  or exits 1
- `open-manifest` — open a token's keyless, advisory manifest
- `forward` — print the forwardable `.0mandate` form of a token

Byte-level conformance ops (the Conformance and test vectors section, §13):

- `seal` / `open` — seal raw octets into a half ciphertext and back
- `parse` — parse a token structurally to JSON

Keys are 128 hex characters or a published-test-key keyword:
`mandate` (the secret test key) wherever a key is taken, and
`manifest` (the public manifest key) for the byte-level `seal` /
`open` ops only — `mint` and `verify` reject the manifest key as a
mandate key (the mandate construction, §5.1). Any token argument may be `-` to read from
stdin.

## Example

```sh
# Mint under the published `mandate` test key, then verify:
TOKEN=$(obsigil mint --key mandate --ttl 3600 --aud api --sub u1 \
          --fields '{"role":"admin"}')
obsigil verify "$TOKEN" --key mandate --audience api
# -> {"exp":...,"tid":"...","app":{"role":"admin"}, ...}
```

## Exit codes

- `0` — success
- `1` — operation rejected (verify/open/parse failure — uniform,
  per the uniform-failure rule of the Security Considerations, §16.6)
- `2` — usage error

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
