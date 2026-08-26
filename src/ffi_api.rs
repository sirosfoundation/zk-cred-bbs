// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! UniFFI-friendly API, consumed by the native SDKs (Kotlin and Swift).
//!
//! Mirrors `zk-cred-vega`'s and `zk-cred-longfellow`'s own `ffi_api.rs`
//! shape: plain `#[uniffi::export]` free functions, an opaque error
//! `Object` wrapping the crate error, `Record`s carrying only FFI-safe
//! types.
//!
//! **No handles.** Unlike the other two crates, nothing here needs a
//! long-lived native object: BBS has no proving key to load and no circuit
//! to compile, and the two-phase issuance/presentation flows already carry
//! their intermediate state as an opaque octet string precisely so it can
//! cross a process, thread, or language boundary while the wallet talks to
//! an authenticator. So every function is bytes in, bytes out.
//!
//! **`ScalarSource::Seeded` is deliberately not exposed.** It exists so the
//! CFRG drafts' vectors and the captured hardware signatures are
//! reproducible; a "use this deterministic seed" knob reachable from
//! Kotlin/Swift is precisely the sort of thing that ends up in production
//! and silently destroys unlinkability. Tests that need it use the Rust API
//! directly.

use crate::blind::{BlindSuite, Disclosure, PLAIN_SUITE_ID, SCHNORR_SUITE_ID};
use crate::error::Error;
use crate::keybind::SchnorrBls12381;
use crate::suite::{ScalarSource, Suite};
use std::fmt::{self, Debug, Display};

/// Opaque error type crossing the UniFFI boundary.
#[derive(uniffi::Object)]
pub struct BbsFfiError(String);

#[uniffi::export]
impl BbsFfiError {
  /// Human-readable description, for logging and diagnostics only —
  /// never surface this to a relying party.
  pub fn message(&self) -> String {
    self.0.clone()
  }
}

impl Debug for BbsFfiError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    Debug::fmt(&self.0, f)
  }
}

impl Display for BbsFfiError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    Display::fmt(&self.0, f)
  }
}

impl std::error::Error for BbsFfiError {}

impl From<Error> for BbsFfiError {
  fn from(e: Error) -> Self {
    BbsFfiError(e.to_string())
  }
}

/// Which key binding construction, and therefore which domain separation,
/// this credential uses.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum BbsSuiteId {
  /// Blind BBS with no device binding.
  Plain,
  /// Blind BBS with Schnorr-on-BLS12-381-G1 device binding — the profile
  /// in `PROFILE.md`.
  Schnorr,
}

impl BbsSuiteId {
  fn as_str(self) -> &'static str {
    match self {
      BbsSuiteId::Plain => PLAIN_SUITE_ID,
      BbsSuiteId::Schnorr => SCHNORR_SUITE_ID,
    }
  }
}

/// Per-message disclosure choice at presentation time.
#[derive(uniffi::Enum, Clone, Copy, PartialEq, Eq)]
pub enum BbsDisclosure {
  Disclose,
  Hide,
  Commit,
}

impl From<BbsDisclosure> for Disclosure {
  fn from(d: BbsDisclosure) -> Self {
    match d {
      BbsDisclosure::Disclose => Disclosure::Disclose,
      BbsDisclosure::Hide => Disclosure::Hide,
      BbsDisclosure::Commit => Disclosure::Commit,
    }
  }
}

/// Output of [`commit_init`].
#[derive(uniffi::Record)]
pub struct CommitInitResult {
  /// Opaque state to hand back to [`commit_finalize`]. Not secret, but
  /// not useful to anyone else either.
  pub state: Vec<u8>,
  /// **Long-lived credential secret.** Must be stored alongside the
  /// credential and is required for every future presentation; losing it
  /// makes the credential unusable, and it must never leave the wallet.
  pub secret_prover_blind: Vec<u8>,
  /// The challenge for the authenticator to sign, once per key binding
  /// key.
  pub challenge: Vec<u8>,
}

/// Output of [`blind_proof_gen_init`].
#[derive(uniffi::Record)]
pub struct ProofGenInitResult {
  /// Opaque state to hand back to [`blind_proof_gen_finalize`].
  pub state: Vec<u8>,
  /// One challenge per key binding key, already SHA-256'd — hand each
  /// straight to the authenticator as the message to be signed. See
  /// `PROFILE.md` DELTA 3 for why the prehash is here.
  pub keybind_challenges: Vec<Vec<u8>>,
  /// Values of the messages marked `Commit`, in order.
  pub committed_values: Vec<Vec<u8>>,
  /// Blinding factors for those commitments, in the same order.
  pub committed_blindings: Vec<Vec<u8>>,
}

fn suite(id: BbsSuiteId) -> BlindSuite<SchnorrBls12381> {
  BlindSuite::new(Suite::new(ScalarSource::System), SchnorrBls12381, id.as_str())
}

fn scalar_bytes(s: &bls12_381_plus::Scalar) -> Vec<u8> {
  s.to_be_bytes().to_vec()
}

/// Begin blind issuance: commit to the messages the issuer will not see, and
/// to the key binding public keys.
///
/// The returned `challenge` must be signed by each authenticator before
/// calling [`commit_finalize`].
#[uniffi::export]
pub fn commit_init(suite_id: BbsSuiteId, committed_messages: Vec<Vec<u8>>, keybind_public_keys: Vec<Vec<u8>>) -> Result<CommitInitResult, BbsFfiError> {
  let s = suite(suite_id);
  let (state, secret_prover_blind, challenge) = s.commit_init(&committed_messages, &keybind_public_keys)?;
  Ok(CommitInitResult {
    state,
    secret_prover_blind: scalar_bytes(&secret_prover_blind),
    challenge: scalar_bytes(&challenge),
  })
}

/// Complete the commitment with the authenticator's signatures. The result
/// is what goes to the issuer.
#[uniffi::export]
pub fn commit_finalize(suite_id: BbsSuiteId, state: Vec<u8>, keybind_signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, BbsFfiError> {
  Ok(suite(suite_id).commit_finalize(&state, &keybind_signatures)?)
}

/// Check that the issuer signed what it was supposed to.
///
/// **Call this before storing a credential.** An issuer that signed a
/// different message set, or bound a different key, produces a credential
/// that fails at presentation time with no useful diagnostic.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn verify_blind_sign(
  suite_id: BbsSuiteId,
  public_key: Vec<u8>,
  signature: Vec<u8>,
  header: Vec<u8>,
  messages: Vec<Vec<u8>>,
  issuer_known_messages_no: u32,
  keybind_public_keys: Vec<Vec<u8>>,
  secret_prover_blind: Vec<u8>,
) -> Result<(), BbsFfiError> {
  let blind = crate::bbs::scalar_from_be(&secret_prover_blind).map_err(BbsFfiError::from)?;
  suite(suite_id).verify_blind_sign(
    &public_key,
    &signature,
    &header,
    &messages,
    issuer_known_messages_no as usize,
    &keybind_public_keys,
    &blind,
  )?;
  Ok(())
}

/// Begin a presentation. Sign each returned `keybind_challenges` entry with
/// the corresponding authenticator, then call
/// [`blind_proof_gen_finalize`].
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn blind_proof_gen_init(
  suite_id: BbsSuiteId,
  public_key: Vec<u8>,
  signature: Vec<u8>,
  header: Vec<u8>,
  presentation_header: Vec<u8>,
  messages: Vec<Vec<u8>>,
  issuer_known_messages_no: u32,
  disclosures: Vec<BbsDisclosure>,
  keybind_public_keys: Vec<Vec<u8>>,
  secret_prover_blind: Vec<u8>,
) -> Result<ProofGenInitResult, BbsFfiError> {
  let blind = crate::bbs::scalar_from_be(&secret_prover_blind).map_err(BbsFfiError::from)?;
  let disclosures: Vec<Disclosure> = disclosures.into_iter().map(Into::into).collect();
  let (state, (values, blindings), keybind_challenges) = suite(suite_id).blind_proof_gen_init(
    &public_key,
    &signature,
    &header,
    &presentation_header,
    &messages,
    issuer_known_messages_no as usize,
    &disclosures,
    &keybind_public_keys,
    &blind,
  )?;
  Ok(ProofGenInitResult {
    state,
    keybind_challenges,
    committed_values: values.iter().map(scalar_bytes).collect(),
    committed_blindings: blindings.iter().map(scalar_bytes).collect(),
  })
}

/// Complete the presentation with the authenticator's signatures.
#[uniffi::export]
pub fn blind_proof_gen_finalize(suite_id: BbsSuiteId, state: Vec<u8>, keybind_signatures: Vec<Vec<u8>>) -> Result<Vec<u8>, BbsFfiError> {
  Ok(suite(suite_id).blind_proof_gen_finalize(&state, &keybind_signatures)?)
}

/// Verify a presentation. Exposed here mainly so a wallet can check its own
/// output in tests — a real relying party verifies in Go, over the C ABI in
/// `go_ffi.rs`.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn blind_proof_verify(
  suite_id: BbsSuiteId,
  public_key: Vec<u8>,
  proof: Vec<u8>,
  header: Vec<u8>,
  presentation_header: Vec<u8>,
  issuer_known_messages_no: u32,
  disclosed_messages: Vec<Vec<u8>>,
  disclosures: Vec<BbsDisclosure>,
) -> Result<(), BbsFfiError> {
  let disclosures: Vec<Disclosure> = disclosures.into_iter().map(Into::into).collect();
  suite(suite_id).blind_proof_verify(
    &public_key,
    &proof,
    &header,
    &presentation_header,
    issuer_known_messages_no as usize,
    &disclosed_messages,
    &disclosures,
  )?;
  Ok(())
}
