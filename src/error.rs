// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

use core::fmt;

/// Every failure this crate can produce.
///
/// Deliberately coarse: a verifier must not learn *why* a proof failed
/// beyond "it failed", and the FFI boundaries (UniFFI, cgo, wasm) all
/// flatten errors to a string anyway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
  /// An input octet string was the wrong length, or a length-prefixed
  /// field exceeded the range the spec allows.
  InvalidLength { what: &'static str, expected: usize, got: usize },
  /// A point failed deserialization, was the identity where the spec
  /// forbids it, or failed the subgroup check.
  InvalidPoint(&'static str),
  /// A scalar was zero or >= r where the spec forbids it.
  InvalidScalar(&'static str),
  /// Two related inputs disagreed on length (messages vs generators,
  /// disclosed messages vs disclosed indexes, ...).
  MismatchedLengths { what: &'static str, a: usize, b: usize },
  /// A message index was outside `0..L`.
  IndexOutOfRange { index: usize, len: usize },
  /// A count exceeded what the spec permits (e.g. `>= 2^64` messages).
  TooMany(&'static str),
  /// The signature, proof, or key binding signature did not verify.
  ///
  /// Intentionally carries only a static discriminator, never the
  /// offending values.
  VerificationFailed(&'static str),
  /// A caller-supplied signing callback failed.
  SignerFailed(String),
  /// The caller combined options the profile does not allow.
  Unsupported(&'static str),
  /// A credential container was structurally malformed.
  ///
  /// The only variant carrying a dynamic message. That is deliberate and
  /// does not weaken the coarseness above: this is a *format* fault, found
  /// before any secret is involved, and naming the offending header
  /// parameter or message index costs an implementer hours while telling
  /// an attacker nothing they did not already supply.
  MalformedContainer(String),
}

impl fmt::Display for Error {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Error::InvalidLength { what, expected, got } => {
        write!(f, "invalid length for {what}: expected {expected}, got {got}")
      }
      Error::InvalidPoint(what) => write!(f, "invalid point: {what}"),
      Error::InvalidScalar(what) => write!(f, "invalid scalar: {what}"),
      Error::MismatchedLengths { what, a, b } => {
        write!(f, "mismatched lengths for {what}: {a} vs {b}")
      }
      Error::IndexOutOfRange { index, len } => {
        write!(f, "index {index} out of range for length {len}")
      }
      Error::TooMany(what) => write!(f, "too many {what}"),
      Error::VerificationFailed(what) => write!(f, "verification failed: {what}"),
      Error::SignerFailed(msg) => write!(f, "signer failed: {msg}"),
      Error::Unsupported(what) => write!(f, "unsupported: {what}"),
      Error::MalformedContainer(msg) => write!(f, "malformed container: {msg}"),
    }
  }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
