// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! `wasm-bindgen` API for browser wallets — the target that lets
//! `wallet-common` / `wallet-frontend` run the same implementation as the
//! native SDKs instead of a parallel TypeScript one.
//!
//! ## Why the split API matters more here than anywhere else
//!
//! Longfellow's browser prover runs entirely inside a web worker, because
//! it is one long computation with no user interaction. BBS is the
//! opposite: the arithmetic is cheap, but there is a **WebAuthn call in the
//! middle**, and WebAuthn requires the main thread and a user gesture.
//!
//! So the intended shape is: wasm computes in a worker →
//! `state`/`keybindChallenges` are transferred to the main thread → the
//! page calls `navigator.credentials.get()` → the signatures come back →
//! wasm finalizes. `state` is a plain `Uint8Array` for exactly this reason;
//! it is structured-cloneable and carries no live references.
//!
//! Do not add a single-call `prove()` convenience wrapper. It could only
//! work by calling WebAuthn from inside the worker, which does not work.

use wasm_bindgen::prelude::*;

use crate::blind::{BlindSuite, Disclosure, PLAIN_SUITE_ID, SCHNORR_SUITE_ID};
use crate::keybind::SchnorrBls12381;
use crate::suite::{ScalarSource, Suite};

fn err(e: crate::Error) -> JsValue {
  JsValue::from_str(&e.to_string())
}

fn suite_for(suite_id: &str) -> Result<BlindSuite<SchnorrBls12381>, JsValue> {
  let id = match suite_id {
    "plain" => PLAIN_SUITE_ID,
    "schnorr" => SCHNORR_SUITE_ID,
    _ => return Err(JsValue::from_str("unknown suite: expected \"plain\" or \"schnorr\"")),
  };
  Ok(BlindSuite::new(Suite::new(ScalarSource::System), SchnorrBls12381, id))
}

fn disclosures_from(codes: &[u8]) -> Result<Vec<Disclosure>, JsValue> {
  codes
    .iter()
    .map(|c| match *c {
      0 => Ok(Disclosure::Disclose),
      1 => Ok(Disclosure::Hide),
      2 => Ok(Disclosure::Commit),
      _ => Err(JsValue::from_str("unknown disclosure code: expected 0, 1 or 2")),
    })
    .collect()
}

/// JS passes arrays of byte arrays as an array of `Uint8Array`.
fn byte_arrays(value: &js_sys::Array) -> Result<Vec<Vec<u8>>, JsValue> {
  value
    .iter()
    .map(|v| {
      let arr: js_sys::Uint8Array = v.dyn_into().map_err(|_| JsValue::from_str("expected an array of Uint8Array"))?;
      Ok(arr.to_vec())
    })
    .collect()
}

fn to_js_arrays(items: &[Vec<u8>]) -> js_sys::Array {
  let out = js_sys::Array::new();
  for item in items {
    out.push(&js_sys::Uint8Array::from(item.as_slice()).into());
  }
  out
}

/// Result of [`commit_init`].
#[wasm_bindgen]
pub struct CommitInit {
  state: Vec<u8>,
  secret_prover_blind: Vec<u8>,
  challenge: Vec<u8>,
}

#[wasm_bindgen]
impl CommitInit {
  /// Opaque state for [`commit_finalize`]. Structured-cloneable.
  #[wasm_bindgen(getter)]
  pub fn state(&self) -> Vec<u8> {
    self.state.clone()
  }

  /// **Long-lived credential secret** — store it with the credential, and
  /// never let it leave the wallet.
  #[wasm_bindgen(getter, js_name = secretProverBlind)]
  pub fn secret_prover_blind(&self) -> Vec<u8> {
    self.secret_prover_blind.clone()
  }

  /// The challenge each authenticator must sign.
  #[wasm_bindgen(getter)]
  pub fn challenge(&self) -> Vec<u8> {
    self.challenge.clone()
  }
}

/// Result of [`blind_proof_gen_init`].
#[wasm_bindgen]
pub struct ProofGenInit {
  state: Vec<u8>,
  keybind_challenges: Vec<Vec<u8>>,
  committed_values: Vec<Vec<u8>>,
  committed_blindings: Vec<Vec<u8>>,
}

#[wasm_bindgen]
impl ProofGenInit {
  /// Opaque state for [`blind_proof_gen_finalize`]. Transfer this to the
  /// main thread alongside `keybindChallenges`.
  #[wasm_bindgen(getter)]
  pub fn state(&self) -> Vec<u8> {
    self.state.clone()
  }

  /// One already-hashed challenge per key binding key — hand each
  /// straight to the authenticator as the message to sign.
  #[wasm_bindgen(getter, js_name = keybindChallenges)]
  pub fn keybind_challenges(&self) -> js_sys::Array {
    to_js_arrays(&self.keybind_challenges)
  }

  /// Values of the messages marked `COMMIT`.
  #[wasm_bindgen(getter, js_name = committedValues)]
  pub fn committed_values(&self) -> js_sys::Array {
    to_js_arrays(&self.committed_values)
  }

  /// Blinding factors for those commitments, in the same order.
  #[wasm_bindgen(getter, js_name = committedBlindings)]
  pub fn committed_blindings(&self) -> js_sys::Array {
    to_js_arrays(&self.committed_blindings)
  }
}

/// Begin blind issuance. `suiteId` is `"plain"` or `"schnorr"`.
#[wasm_bindgen(js_name = commitInit)]
pub fn commit_init(suite_id: &str, committed_messages: &js_sys::Array, keybind_public_keys: &js_sys::Array) -> Result<CommitInit, JsValue> {
  let s = suite_for(suite_id)?;
  let (state, blind, challenge) = s
    .commit_init(&byte_arrays(committed_messages)?, &byte_arrays(keybind_public_keys)?)
    .map_err(err)?;
  Ok(CommitInit {
    state,
    secret_prover_blind: blind.to_be_bytes().to_vec(),
    challenge: challenge.to_be_bytes().to_vec(),
  })
}

/// Complete the commitment with the authenticator's signatures.
#[wasm_bindgen(js_name = commitFinalize)]
pub fn commit_finalize(suite_id: &str, state: &[u8], keybind_signatures: &js_sys::Array) -> Result<Vec<u8>, JsValue> {
  suite_for(suite_id)?.commit_finalize(state, &byte_arrays(keybind_signatures)?).map_err(err)
}

/// Check the issuer signed what it was supposed to. Call before storing.
#[wasm_bindgen(js_name = verifyBlindSign)]
#[allow(clippy::too_many_arguments)]
pub fn verify_blind_sign(
  suite_id: &str,
  public_key: &[u8],
  signature: &[u8],
  header: &[u8],
  messages: &js_sys::Array,
  issuer_known_messages_no: usize,
  keybind_public_keys: &js_sys::Array,
  secret_prover_blind: &[u8],
) -> Result<(), JsValue> {
  let blind = crate::bbs::scalar_from_be(secret_prover_blind).map_err(err)?;
  suite_for(suite_id)?
    .verify_blind_sign(
      public_key,
      signature,
      header,
      &byte_arrays(messages)?,
      issuer_known_messages_no,
      &byte_arrays(keybind_public_keys)?,
      &blind,
    )
    .map_err(err)
}

/// Begin a presentation. Sign each `keybindChallenges` entry on the main
/// thread, then call [`blind_proof_gen_finalize`].
#[wasm_bindgen(js_name = blindProofGenInit)]
#[allow(clippy::too_many_arguments)]
pub fn blind_proof_gen_init(
  suite_id: &str,
  public_key: &[u8],
  signature: &[u8],
  header: &[u8],
  presentation_header: &[u8],
  messages: &js_sys::Array,
  issuer_known_messages_no: usize,
  disclosures: &[u8],
  keybind_public_keys: &js_sys::Array,
  secret_prover_blind: &[u8],
) -> Result<ProofGenInit, JsValue> {
  let blind = crate::bbs::scalar_from_be(secret_prover_blind).map_err(err)?;
  let (state, (values, blindings), keybind_challenges) = suite_for(suite_id)?
    .blind_proof_gen_init(
      public_key,
      signature,
      header,
      presentation_header,
      &byte_arrays(messages)?,
      issuer_known_messages_no,
      &disclosures_from(disclosures)?,
      &byte_arrays(keybind_public_keys)?,
      &blind,
    )
    .map_err(err)?;
  Ok(ProofGenInit {
    state,
    keybind_challenges,
    committed_values: values.iter().map(|s| s.to_be_bytes().to_vec()).collect(),
    committed_blindings: blindings.iter().map(|s| s.to_be_bytes().to_vec()).collect(),
  })
}

/// Complete the presentation with the authenticator's signatures.
#[wasm_bindgen(js_name = blindProofGenFinalize)]
pub fn blind_proof_gen_finalize(suite_id: &str, state: &[u8], keybind_signatures: &js_sys::Array) -> Result<Vec<u8>, JsValue> {
  suite_for(suite_id)?
    .blind_proof_gen_finalize(state, &byte_arrays(keybind_signatures)?)
    .map_err(err)
}

/// Verify a presentation. Present mainly so a wallet can check its own
/// output; a real relying party verifies server-side.
#[wasm_bindgen(js_name = blindProofVerify)]
#[allow(clippy::too_many_arguments)]
pub fn blind_proof_verify(
  suite_id: &str,
  public_key: &[u8],
  proof: &[u8],
  header: &[u8],
  presentation_header: &[u8],
  issuer_known_messages_no: usize,
  disclosed_messages: &js_sys::Array,
  disclosures: &[u8],
) -> Result<(), JsValue> {
  suite_for(suite_id)?
    .blind_proof_verify(
      public_key,
      proof,
      header,
      presentation_header,
      issuer_known_messages_no,
      &byte_arrays(disclosed_messages)?,
      &disclosures_from(disclosures)?,
    )
    .map_err(err)
}
