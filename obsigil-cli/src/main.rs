//! `obsigil` — command-line tool for the obsigil mandate-token format.
//!
//! High-level: `mint`, `verify`, `open-manifest`, `forward`. Byte-level
//! conformance ops (spec §10): `seal`, `open`, `parse`. Keys are given as
//! 128 hex chars or a published-test-key keyword: `mandate` (the secret test
//! key, SHA-512("obsigil test mandate key v1")) wherever a key is taken, and
//! `manifest` (the public manifest key from the spec) for the byte-level
//! `seal`/`open` ops only — `mint`/`verify` reject it as a mandate key
//! (spec §4.1).
//!
//! Exit codes: 0 success; 1 operation rejected (verify/open/parse failure —
//! uniform, per spec §9.5); 2 usage error.

use std::io::Read;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use obsigil::lowlevel::{self, Alg, Encoding};
use obsigil::{open_manifest, Issuer, MandateKey, Uuid, Verifier};
use serde_json::{json, Value};

/// The published test mandate key: SHA-512("obsigil test mandate key v1"),
/// distinct from the manifest key (spec §4.1). Used by `--key mandate`.
const MANDATE_TEST_KEY_HEX: &str =
    "a341adc813cfa493412cda5900fa4ec83f20a6cdea4fe5c759f7ccdb7ffbec51\
e01d2ce90c592909adb2ac1cad771790353f439ac86e9b113a17f7c57f0684b0";

#[derive(Parser)]
#[command(name = "obsigil", version, about = "obsigil mandate-token CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
// `Mint` carries many flags; boxing it would fight clap's derive.
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Mint a token from clauses (and optionally a manifest).
    Mint(MintArgs),
    /// Verify a token's mandate; prints clauses JSON or exits 1.
    Verify(VerifyArgs),
    /// Open a token's manifest (keyless, advisory); prints claims JSON.
    OpenManifest(TokenArg),
    /// Print the forwardable `.0mandate` form of a token.
    Forward(TokenArg),
    /// Seal raw octets (hex) into a half ciphertext (conformance).
    Seal(SealArgs),
    /// Open a half ciphertext back to raw octets (hex) (conformance).
    Open(OpenArgs),
    /// Parse a token structurally; prints JSON or exits 1 (conformance).
    Parse(TokenArg),
}

#[derive(Args)]
struct MintArgs {
    /// Mandate key: 128 hex chars, or `mandate` (the published test key).
    #[arg(short = 'k', long)]
    key: String,
    /// Expiry as a NumericDate (seconds since the Unix epoch).
    #[arg(long)]
    exp: Option<i64>,
    /// Expiry as a TTL in seconds from now (alternative to --exp).
    #[arg(long)]
    ttl: Option<u64>,
    /// tid (UUIDv7); generated if omitted.
    #[arg(long)]
    tid: Option<String>,
    /// Audience(s), comma-separated.
    #[arg(long, value_delimiter = ',')]
    aud: Vec<String>,
    /// Subject.
    #[arg(long)]
    sub: Option<String>,
    /// Mandate issuer (for audit).
    #[arg(long)]
    iss: Option<String>,
    /// Mandate algorithm code: 0 (AES-SIV) | 1 (AES-GCM-SIV).
    #[arg(long, default_value = "0")]
    alg: String,
    /// Token text encoding: b64 | hex.
    #[arg(short = 'e', long, default_value = "b64")]
    encoding: String,
    /// Application clauses as a JSON object (default `{}`); `-` reads stdin.
    #[arg(long)]
    fields: Option<String>,
    /// Include a manifest with this required `iss` claim (keyless).
    #[arg(long)]
    manifest_iss: Option<String>,
    /// Manifest application claims as a JSON object.
    #[arg(long)]
    manifest_fields: Option<String>,
    /// Manifest algorithm code: 0 (AES-SIV) | 1 (AES-GCM-SIV).
    #[arg(long, default_value = "0")]
    manifest_alg: String,
}

#[derive(Args)]
struct VerifyArgs {
    /// Token (or `-` for stdin).
    token: String,
    /// Candidate mandate key(s); repeatable. Hex, or `mandate`.
    #[arg(short = 'k', long)]
    key: Vec<String>,
    /// This verifier's audience identifier.
    #[arg(short = 'a', long)]
    audience: Option<String>,
    /// Clock-skew leeway in seconds.
    #[arg(long, default_value_t = 0)]
    leeway: u64,
    /// Pin "now" (seconds since the Unix epoch).
    #[arg(long)]
    now: Option<i64>,
    /// Print the internal rejection reason to stderr (debugging only).
    #[arg(long)]
    reason: bool,
}

#[derive(Args)]
struct SealArgs {
    /// Raw octets (a half's canonical CBOR plaintext) as hex; `-` reads stdin.
    #[arg(long)]
    octets: String,
    /// Key: 128 hex chars, or `manifest` / `mandate`.
    #[arg(short = 'k', long)]
    key: String,
    /// Algorithm code: 0 | 1.
    #[arg(long, default_value = "0")]
    alg: String,
    /// Text encoding: b64 | hex.
    #[arg(short = 'e', long, default_value = "b64")]
    encoding: String,
}

#[derive(Args)]
struct OpenArgs {
    /// The half ciphertext text.
    #[arg(long)]
    half: String,
    /// Key: 128 hex chars, or `manifest` / `mandate`.
    #[arg(short = 'k', long)]
    key: String,
    /// Algorithm code: 0 | 1.
    #[arg(long, default_value = "0")]
    alg: String,
    /// Text encoding: b64 | hex.
    #[arg(short = 'e', long, default_value = "b64")]
    encoding: String,
}

#[derive(Args)]
struct TokenArg {
    /// Token (or `-` for stdin).
    token: String,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.cmd {
        Cmd::Mint(a) => cmd_mint(a),
        Cmd::Verify(a) => cmd_verify(a),
        Cmd::OpenManifest(a) => cmd_open_manifest(a),
        Cmd::Forward(a) => cmd_forward(a),
        Cmd::Seal(a) => cmd_seal(a),
        Cmd::Open(a) => cmd_open(a),
        Cmd::Parse(a) => cmd_parse(a),
    }
}

fn cmd_mint(a: MintArgs) -> Result<ExitCode, String> {
    let key = MandateKey::from_bytes(resolve_key(&a.key)?).map_err(|e| e.to_string())?;
    let issuer = Issuer::new(key)
        .alg(parse_alg(&a.alg)?)
        .manifest_alg(parse_alg(&a.manifest_alg)?)
        .encoding(parse_encoding(&a.encoding)?);

    let fields = read_input(a.fields.as_deref().unwrap_or("{}"))?;
    let app: Value = serde_json::from_str(&fields).map_err(|e| format!("--fields: {e}"))?;

    let mut b = issuer.mandate(&app);
    b = match (a.exp, a.ttl) {
        (Some(exp), _) => b.exp(exp),
        (None, Some(ttl)) => b.expires_in(Duration::from_secs(ttl)),
        (None, None) => return Err("one of --exp or --ttl is required".into()),
    };
    if let Some(tid) = &a.tid {
        b = b.tid(Uuid::parse_str(tid).map_err(|e| format!("--tid: {e}"))?);
    }
    if !a.aud.is_empty() {
        b = b.audience(a.aud.clone());
    }
    if let Some(sub) = &a.sub {
        b = b.subject(sub.clone());
    }
    if let Some(iss) = &a.iss {
        b = b.issuer(iss.clone());
    }

    let manifest_app: Value;
    if let Some(miss) = &a.manifest_iss {
        let mfields = read_input(a.manifest_fields.as_deref().unwrap_or("{}"))?;
        manifest_app =
            serde_json::from_str(&mfields).map_err(|e| format!("--manifest-fields: {e}"))?;
        b = b.manifest(miss.clone(), &manifest_app);
    }

    let token = b.mint().map_err(|e| e.to_string())?;
    println!("{token}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(a: VerifyArgs) -> Result<ExitCode, String> {
    let token = read_input(&a.token)?;
    if a.key.is_empty() {
        return Err("at least one --key is required".into());
    }
    let keys: Vec<MandateKey> = a
        .key
        .iter()
        .map(|k| MandateKey::from_bytes(resolve_key(k)?).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;

    let mut v = Verifier::new().leeway(Duration::from_secs(a.leeway));
    for k in &keys {
        v = v.key(k);
    }
    if let Some(aud) = a.audience {
        v = v.audience(aud);
    }
    if let Some(now) = a.now {
        v = v.now(now);
    }

    match v.verify::<Value>(&token) {
        Ok(m) => {
            let out = json!({
                "exp": m.exp(),
                "tid": m.tid().to_string(),
                "issued_at": m.issued_at(),
                "iss": m.issuer(),
                "aud": m.audience(),
                "sub": m.subject(),
                "app": m.app(),
            });
            println!(
                "{}",
                serde_json::to_string(&out).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("obsigil: token rejected");
            if a.reason {
                eprintln!("reason: {:?}", e.reason());
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

fn cmd_open_manifest(a: TokenArg) -> Result<ExitCode, String> {
    let token = read_input(&a.token)?;
    match open_manifest::<Value>(&token) {
        Some(m) => {
            let out = json!({ "iss": m.issuer(), "exp": m.exp(), "app": m.app() });
            println!(
                "{}",
                serde_json::to_string(&out).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::FAILURE),
    }
}

fn cmd_forward(a: TokenArg) -> Result<ExitCode, String> {
    let token = read_input(&a.token)?;
    match lowlevel::parse(&token) {
        Some(p) if p.mandate.is_some() => {
            println!("{}{}", p.separator, p.mandate_part);
            Ok(ExitCode::SUCCESS)
        }
        _ => Ok(ExitCode::FAILURE),
    }
}

fn cmd_seal(a: SealArgs) -> Result<ExitCode, String> {
    let octets_hex = read_input(&a.octets)?;
    let octets =
        lowlevel::decode(&octets_hex, Encoding::Hex).ok_or("--octets must be lowercase hex")?;
    let key = resolve_key(&a.key)?;
    let sealed = lowlevel::seal(&octets, &key, parse_alg(&a.alg)?)
        .ok_or("algorithm not enabled in this build")?;
    println!(
        "{}",
        lowlevel::encode(&sealed, parse_encoding(&a.encoding)?)
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_open(a: OpenArgs) -> Result<ExitCode, String> {
    let key = resolve_key(&a.key)?;
    let encoding = parse_encoding(&a.encoding)?;
    let Some(sealed) = lowlevel::decode(&a.half, encoding) else {
        return Ok(ExitCode::FAILURE);
    };
    match lowlevel::open(&sealed, &key, parse_alg(&a.alg)?) {
        Some(octets) => {
            println!("{}", lowlevel::encode(&octets, Encoding::Hex));
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::FAILURE),
    }
}

fn cmd_parse(a: TokenArg) -> Result<ExitCode, String> {
    let token = read_input(&a.token)?;
    match lowlevel::parse(&token) {
        Some(p) => {
            let encoding = match p.encoding {
                Encoding::B64 => "b64",
                Encoding::Hex => "hex",
            };
            let half = |h: &Option<lowlevel::Half>| {
                h.as_ref()
                    .map(|x| json!({ "alg": x.alg.to_string(), "text": x.text }))
            };
            let out = json!({
                "encoding": encoding,
                "separator": p.separator.to_string(),
                "manifest": half(&p.manifest),
                "mandate": half(&p.mandate),
            });
            println!(
                "{}",
                serde_json::to_string(&out).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(ExitCode::FAILURE),
    }
}

/// Resolve a `--key` value to 64 raw bytes: a role keyword or 128 hex chars.
fn resolve_key(s: &str) -> Result<[u8; 64], String> {
    if s == "manifest" {
        return Ok(obsigil::MANIFEST_KEY);
    }
    let hex = if s == "mandate" {
        MANDATE_TEST_KEY_HEX.to_string()
    } else {
        s.to_lowercase()
    };
    let bytes =
        lowlevel::decode(&hex, Encoding::Hex).ok_or("--key must be hex or `manifest`/`mandate`")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "--key must be 64 bytes (128 hex chars)".to_string())
}

fn parse_alg(s: &str) -> Result<Alg, String> {
    let mut chars = s.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => {
            Alg::from_code(c).ok_or_else(|| format!("unknown/unsupported alg code `{s}`"))
        }
        _ => Err(format!("--alg must be a single code character, got `{s}`")),
    }
}

fn parse_encoding(s: &str) -> Result<Encoding, String> {
    match s {
        "b64" => Ok(Encoding::B64),
        "hex" => Ok(Encoding::Hex),
        _ => Err(format!("--encoding must be b64 or hex, got `{s}`")),
    }
}

/// Return `s`, or read trimmed stdin when `s == "-"`.
fn read_input(s: &str) -> Result<String, String> {
    if s == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("reading stdin: {e}"))?;
        Ok(buf.trim().to_string())
    } else {
        Ok(s.to_string())
    }
}
