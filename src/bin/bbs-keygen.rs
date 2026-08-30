// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Generate a BBS issuer key pair.
//!
//! Writes the two base64url files an issuer's configuration points at —
//! `secret_key_path` and `public_key_path` — because until this existed
//! there was no way to produce them, and an issuer that cannot be given a
//! key cannot issue.
//!
//! ```text
//! bbs-keygen --out-dir /etc/vc/bbs
//! bbs-keygen --out-dir . --key-info "issuer.example.com"
//! bbs-keygen --check --secret issuer.sk --public issuer.pk
//! ```
//!
//! The secret key is written `0600`. It is a BLS12-381 scalar consumed
//! inside the signing algebra rather than a key that signs a digest, so it
//! cannot live in a PKCS#11 HSM — mainstream HSMs do not implement the
//! curve. Treat the file as the whole of the issuer's signing capability.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use zk_cred_bbs::keygen;

fn main() -> ExitCode {
  match run() {
    Ok(()) => ExitCode::SUCCESS,
    Err(message) => {
      eprintln!("bbs-keygen: {message}");
      ExitCode::FAILURE
    }
  }
}

struct Args {
  out_dir: PathBuf,
  key_info: String,
  secret_name: String,
  public_name: String,
  check: bool,
  force: bool,
}

fn run() -> Result<(), String> {
  let args = parse(std::env::args().skip(1).collect())?;

  let secret_path = args.out_dir.join(&args.secret_name);
  let public_path = args.out_dir.join(&args.public_name);

  if args.check {
    let sk = read_base64url(&secret_path)?;
    let pk = read_base64url(&public_path)?;
    keygen::key_pair_matches(&sk, &pk).map_err(|e| format!("{e}"))?;
    println!("ok: {} and {} are a pair", secret_path.display(), public_path.display());
    return Ok(());
  }

  // Refuse rather than overwrite. Silently replacing an issuer's signing
  // key makes every credential it has ever issued unverifiable, and the
  // only symptom is that verification stops working everywhere at once.
  if !args.force {
    for path in [&secret_path, &public_path] {
      if path.exists() {
        return Err(format!("{} already exists; pass --force to replace it", path.display()));
      }
    }
  }

  let (sk, pk) = keygen::key_gen_random(args.key_info.as_bytes()).map_err(|e| format!("{e}"))?;

  fs::create_dir_all(&args.out_dir).map_err(|e| format!("creating {}: {e}", args.out_dir.display()))?;
  write_secret(&secret_path, &base64url(&sk))?;
  write_public(&public_path, &base64url(&pk))?;

  // Cheap, and it means the files on disk are checked rather than only the
  // values in memory a moment ago.
  let on_disk_sk = read_base64url(&secret_path)?;
  let on_disk_pk = read_base64url(&public_path)?;
  keygen::key_pair_matches(&on_disk_sk, &on_disk_pk).map_err(|e| format!("written files do not verify: {e}"))?;

  println!("secret key: {} (mode 0600)", secret_path.display());
  println!("public key: {}", public_path.display());
  println!();
  println!("public key, for a verifier or a wallet's issuer metadata:");
  println!("{}", base64url(&pk));
  Ok(())
}

fn parse(argv: Vec<String>) -> Result<Args, String> {
  let mut args = Args {
    out_dir: PathBuf::from("."),
    key_info: String::new(),
    secret_name: "issuer.sk".to_string(),
    public_name: "issuer.pk".to_string(),
    check: false,
    force: false,
  };

  let mut i = 0;
  while i < argv.len() {
    let take = |i: &mut usize, what: &str| -> Result<String, String> {
      *i += 1;
      argv.get(*i).cloned().ok_or_else(|| format!("{what} needs a value"))
    };
    match argv[i].as_str() {
      "--out-dir" => args.out_dir = PathBuf::from(take(&mut i, "--out-dir")?),
      "--key-info" => args.key_info = take(&mut i, "--key-info")?,
      "--secret" => args.secret_name = take(&mut i, "--secret")?,
      "--public" => args.public_name = take(&mut i, "--public")?,
      "--check" => args.check = true,
      "--force" => args.force = true,
      "-h" | "--help" => {
        print_help();
        std::process::exit(0);
      }
      other => return Err(format!("unknown argument: {other}")),
    }
    i += 1;
  }
  Ok(args)
}

fn print_help() {
  println!(
    "\
Generate a BBS issuer key pair (draft-irtf-cfrg-bbs-signatures-08 §3.4.1).

USAGE:
  bbs-keygen [--out-dir DIR] [--key-info STRING] [--secret NAME] [--public NAME] [--force]
  bbs-keygen --check [--out-dir DIR] [--secret NAME] [--public NAME]

OPTIONS:
  --out-dir DIR      where to write (default: .)
  --key-info STRING  context bound into the derivation, so one seed can yield
                     distinct keys for distinct issuers (default: empty)
  --secret NAME      secret key filename (default: issuer.sk)
  --public NAME      public key filename (default: issuer.pk)
  --check            verify that two existing files are a pair, and write nothing
  --force            replace existing files

Both files hold a single base64url value with no padding. The secret key is
written 0600 and cannot be held in a PKCS#11 HSM: it is a BLS12-381 scalar
consumed inside the signing algebra, and mainstream HSMs do not implement
the curve."
  );
}

fn base64url(data: &[u8]) -> String {
  const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
  for chunk in data.chunks(3) {
    let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
    let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
    let take = chunk.len() + 1;
    for k in 0..take {
      out.push(ALPHABET[((n >> (18 - 6 * k)) & 0x3f) as usize] as char);
    }
  }
  out
}

fn unbase64url(s: &str) -> Result<Vec<u8>, String> {
  let value = |c: u8| -> Result<u32, String> {
    Ok(match c {
      b'A'..=b'Z' => u32::from(c - b'A'),
      b'a'..=b'z' => u32::from(c - b'a') + 26,
      b'0'..=b'9' => u32::from(c - b'0') + 52,
      b'-' => 62,
      b'_' => 63,
      _ => return Err(format!("not base64url: {:?}", c as char)),
    })
  };
  let bytes = s.as_bytes();
  let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
  for chunk in bytes.chunks(4) {
    if chunk.len() == 1 {
      return Err("truncated base64url".to_string());
    }
    let mut n = 0u32;
    for (k, &c) in chunk.iter().enumerate() {
      n |= value(c)? << (18 - 6 * k);
    }
    for k in 0..chunk.len() - 1 {
      out.push(((n >> (16 - 8 * k)) & 0xff) as u8);
    }
  }
  Ok(out)
}

fn read_base64url(path: &Path) -> Result<Vec<u8>, String> {
  let raw = fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
  // Trailing newlines are what every editor leaves behind; padding is what
  // a standard-base64 tool leaves behind. Neither is a broken key.
  unbase64url(raw.trim().trim_end_matches('=')).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
  use std::os::unix::fs::OpenOptionsExt;
  let mut f = fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(path)
    .map_err(|e| format!("writing {}: {e}", path.display()))?;
  writeln!(f, "{contents}").map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
  fs::write(path, format!("{contents}\n")).map_err(|e| format!("writing {}: {e}", path.display()))
}

fn write_public(path: &Path, contents: &str) -> Result<(), String> {
  fs::write(path, format!("{contents}\n")).map_err(|e| format!("writing {}: {e}", path.display()))
}
