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

use crate::blind::{BlindSuite, Disclosure};
use crate::error::Error;
use crate::flow::SuiteId;
use crate::keybind::SchnorrBls12381;
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

impl From<BbsSuiteId> for SuiteId {
  fn from(id: BbsSuiteId) -> Self {
    match id {
      BbsSuiteId::Plain => SuiteId::Plain,
      BbsSuiteId::Schnorr => SuiteId::Schnorr,
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
  crate::flow::suite(id.into())
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

// ---------------------------------------------------------------------------
// The credential container
// ---------------------------------------------------------------------------
//
// The functions above are the BBS algebra: they take a message vector and
// know nothing about what the messages mean. These take a credential.
//
// The mapping between the two lives here, in Rust, rather than in each
// SDK. Four consumers share this crate, and the mapping is exactly the
// kind of thing they would drift apart on - a claim ordering or a
// disclosure index that differs between the issuer and the wallet produces
// a proof that simply does not verify, with nothing in the failure
// pointing at the cause. One implementation cannot disagree with itself.

/// What a stored credential says about itself.
#[derive(uniffi::Record)]
pub struct JwpCredentialInfo {
  /// The SD-JWT VC type identifier, for matching against what a verifier
  /// asked for.
  pub vct: String,
  /// The key binding identifier, absent if the credential is not bound to
  /// a device key.
  pub kb: Option<String>,
  /// Every claim's RFC 6901 pointer, in message order.
  pub pointers: Vec<String>,
  /// How many of the messages the issuer supplied. The remainder are the
  /// holder's own, committed at issuance.
  pub num_signer_messages: u32,
}

/// One claim a verifier learned from a presentation.
#[derive(uniffi::Record)]
pub struct JwpDisclosedClaim {
  /// RFC 6901 pointer naming the claim.
  pub pointer: String,
  /// Its value, as JSON.
  pub value_json: String,
}

/// What a verifier learned from a presentation, after it verified.
#[derive(uniffi::Record)]
pub struct JwpPresentationResult {
  pub vct: String,
  /// Only the claims actually disclosed. Withheld ones are absent, not
  /// null - the verifier does not learn they exist beyond their pointer
  /// appearing in the header's map.
  pub disclosed: Vec<JwpDisclosedClaim>,
}

/// Output of [`jwp_committed_messages`].
#[derive(uniffi::Record)]
pub struct JwpCommittedMessages {
  /// The messages to hand to [`commit_init`], in order.
  pub messages: Vec<Vec<u8>>,
  /// Their RFC 6901 pointers, in the same order. These go in the credential
  /// request; the issuer needs them to build the credential's map and
  /// checks their count against the commitment.
  pub pointers: Vec<String>,
}

/// Output of [`jwp_present_init`].
#[derive(uniffi::Record)]
pub struct JwpPresentInitResult {
  /// Opaque state for [`jwp_present_finalize`].
  pub state: Vec<u8>,
  /// One challenge per key binding key, already prehashed - hand each
  /// straight to the authenticator. See `PROFILE.md` DELTA 3.
  pub keybind_challenges: Vec<Vec<u8>>,
}

// Everything below is a type adapter over `crate::flow`, which holds the
// actual flow logic. Kotlin and Swift see UniFFI records; the browser sees
// `wasm_bindgen` objects; Go sees JSON over the C ABI - but all three run
// the same code, so a claim cannot be numbered one way here and another
// way there.

impl From<crate::flow::CredentialInfo> for JwpCredentialInfo {
  fn from(i: crate::flow::CredentialInfo) -> Self {
    Self {
      vct: i.vct,
      kb: i.kb,
      pointers: i.pointers,
      num_signer_messages: i.num_signer_messages as u32,
    }
  }
}

/// The holder's own claims, turned into the messages it commits to.
///
/// The wallet's first step in blind issuance. It has claims by name and
/// needs the ordered octet strings [`commit_init`] takes, in the same order
/// the issuer will later assign message indices in - otherwise the
/// credential's map names one claim while the signature covers another.
///
/// Note what is NOT needed here: the issuer's message count. Indices go in
/// the header's map, which the issuer builds; the message octets are just
/// the claim values, so the wallet can commit before it knows how many
/// claims the issuer will add.
///
/// Returns the pointers alongside the messages because the credential
/// request must carry them - the issuer never sees these values and cannot
/// name them itself.
#[uniffi::export]
pub fn jwp_committed_messages(claims_json: String) -> Result<JwpCommittedMessages, BbsFfiError> {
  let out = crate::flow::committed_messages(&claims_json)?;
  Ok(JwpCommittedMessages {
    messages: out.messages,
    pointers: out.pointers,
  })
}

/// Read a stored credential without verifying it.
///
/// For deciding whether this credential can satisfy a request. It parses
/// and structurally validates the container, but proves nothing about the
/// signature - use [`jwp_accept`] for that.
#[uniffi::export]
pub fn jwp_inspect(issued_jwp: String) -> Result<JwpCredentialInfo, BbsFfiError> {
  Ok(crate::flow::inspect(&issued_jwp)?.into())
}

/// Check a freshly issued credential before storing it.
///
/// This is not optional. It is the holder's only chance to find out that
/// the issuer signed something other than what was asked for, or that the
/// credential is not actually bound to the device key that was committed -
/// both of which otherwise surface much later, as a presentation that will
/// not verify.
#[uniffi::export]
pub fn jwp_accept(
  suite_id: BbsSuiteId,
  issued_jwp: String,
  issuer_public_key: Vec<u8>,
  committed_messages: Vec<Vec<u8>>,
  keybind_public_keys: Vec<Vec<u8>>,
  secret_prover_blind: Vec<u8>,
) -> Result<JwpCredentialInfo, BbsFfiError> {
  Ok(
    crate::flow::accept(
      suite_id.into(),
      &issued_jwp,
      &issuer_public_key,
      &committed_messages,
      &keybind_public_keys,
      &secret_prover_blind,
    )?
    .into(),
  )
}

/// Begin a presentation, disclosing exactly `requested_pointers`.
///
/// Splits around the authenticator signature for the same reason
/// [`blind_proof_gen_init`] does: the device signs in the middle, and on
/// the web that happens on a different thread than the computation.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn jwp_present_init(
  suite_id: BbsSuiteId,
  issued_jwp: String,
  issuer_public_key: Vec<u8>,
  presentation_header: Vec<u8>,
  requested_pointers: Vec<String>,
  committed_messages: Vec<Vec<u8>>,
  keybind_public_keys: Vec<Vec<u8>>,
  secret_prover_blind: Vec<u8>,
) -> Result<JwpPresentInitResult, BbsFfiError> {
  let out = crate::flow::present_init(
    suite_id.into(),
    &issued_jwp,
    &issuer_public_key,
    &presentation_header,
    &requested_pointers,
    &committed_messages,
    &keybind_public_keys,
    &secret_prover_blind,
  )?;
  Ok(JwpPresentInitResult {
    state: out.state,
    keybind_challenges: out.keybind_challenges,
  })
}

/// Complete the presentation, returning the compact presented JWP.
#[uniffi::export]
pub fn jwp_present_finalize(suite_id: BbsSuiteId, state: Vec<u8>, keybind_signatures: Vec<Vec<u8>>) -> Result<String, BbsFfiError> {
  Ok(crate::flow::present_finalize(suite_id.into(), &state, &keybind_signatures)?)
}

/// Verify a presentation and return what it disclosed.
///
/// A wallet uses this to check its own output. A relying party would too,
/// but in Go over the C ABI - the important property is that it is the
/// same code either way.
#[uniffi::export]
pub fn jwp_verify(suite_id: BbsSuiteId, presented_jwp: String, issuer_public_key: Vec<u8>) -> Result<JwpPresentationResult, BbsFfiError> {
  let out = crate::flow::verify(suite_id.into(), &presented_jwp, &issuer_public_key)?;
  Ok(JwpPresentationResult {
    vct: out.vct,
    disclosed: out
      .disclosed
      .into_iter()
      .map(|d| JwpDisclosedClaim {
        pointer: d.pointer,
        value_json: d.value_json,
      })
      .collect(),
  })
}

/// Build a Presentation Header.
///
/// `extra_json`, if given, is a JSON object whose members are merged in -
/// the profile needs somewhere to bind a transport's own session
/// transcript, and which member that is belongs to the SDK, not here.
#[uniffi::export]
pub fn jwp_build_presentation_header(nonce: String, aud: String, extra_json: Option<String>) -> Result<Vec<u8>, BbsFfiError> {
  Ok(crate::flow::build_presentation_header(&nonce, &aud, extra_json.as_deref())?)
}
