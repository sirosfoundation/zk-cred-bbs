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

use crate::blind::{BlindSuite, Disclosure};
use crate::keybind::SchnorrBls12381;

fn err(e: crate::Error) -> JsValue {
  JsValue::from_str(&e.to_string())
}

fn suite_id_for(suite_id: &str) -> Result<crate::flow::SuiteId, JsValue> {
  crate::flow::SuiteId::parse(suite_id).map_err(err)
}

fn suite_for(suite_id: &str) -> Result<BlindSuite<SchnorrBls12381>, JsValue> {
  Ok(crate::flow::suite(suite_id_for(suite_id)?))
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

// The credential-level API. Everything above operates on message vectors;
// everything below operates on claims and JWP containers, which is what a
// browser wallet actually holds.
//
// These exist here rather than being left to TypeScript because the
// claim-to-message mapping - which claim is message 3, in what order, with
// what pointer - is part of what the signature covers. A second
// implementation of it in the page would not fail at the boundary; it
// would produce credentials that verify nowhere, months later. Same
// argument as the native SDKs, same code: `crate::flow`.

/// What a stored credential says about itself.
#[wasm_bindgen]
pub struct CredentialInfo {
  inner: crate::flow::CredentialInfo,
}

#[wasm_bindgen]
impl CredentialInfo {
  /// The SD-JWT VC type identifier, for matching against what a verifier
  /// asked for.
  #[wasm_bindgen(getter)]
  pub fn vct(&self) -> String {
    self.inner.vct.clone()
  }

  /// The key binding identifier, `undefined` if the credential is not
  /// bound to a device key.
  #[wasm_bindgen(getter)]
  pub fn kb(&self) -> Option<String> {
    self.inner.kb.clone()
  }

  /// Every claim's RFC 6901 pointer, in message order.
  #[wasm_bindgen(getter)]
  pub fn pointers(&self) -> Vec<String> {
    self.inner.pointers.clone()
  }

  /// How many of the messages the issuer supplied. The remainder are the
  /// holder's own, committed at issuance.
  #[wasm_bindgen(getter, js_name = numSignerMessages)]
  pub fn num_signer_messages(&self) -> usize {
    self.inner.num_signer_messages
  }
}

/// Result of [`jwp_committed_messages`].
#[wasm_bindgen]
pub struct CommittedMessages {
  inner: crate::flow::CommittedMessages,
}

#[wasm_bindgen]
impl CommittedMessages {
  /// The messages to hand to [`commit_init`], in order.
  #[wasm_bindgen(getter)]
  pub fn messages(&self) -> js_sys::Array {
    to_js_arrays(&self.inner.messages)
  }

  /// Their RFC 6901 pointers, in the same order. These go in the
  /// credential request; the issuer needs them to build the credential's
  /// map and checks their count against the commitment.
  #[wasm_bindgen(getter)]
  pub fn pointers(&self) -> Vec<String> {
    self.inner.pointers.clone()
  }
}

/// Result of [`jwp_present_init`].
#[wasm_bindgen]
pub struct PresentInit {
  inner: crate::flow::PresentInit,
}

#[wasm_bindgen]
impl PresentInit {
  /// Opaque state for [`jwp_present_finalize`]. Transfer this to the main
  /// thread alongside `keybindChallenges`.
  #[wasm_bindgen(getter)]
  pub fn state(&self) -> Vec<u8> {
    self.inner.state.clone()
  }

  /// One already-hashed challenge per key binding key.
  #[wasm_bindgen(getter, js_name = keybindChallenges)]
  pub fn keybind_challenges(&self) -> js_sys::Array {
    to_js_arrays(&self.inner.keybind_challenges)
  }
}

#[wasm_bindgen]
extern "C" {
  /// The disclosed claims, typed for TypeScript. Values are `unknown`
  /// rather than `string`: a claim is whatever JSON the issuer signed.
  #[wasm_bindgen(typescript_type = "Record<string, unknown>")]
  pub type DisclosedClaims;
}

/// What a verifier learned from a presentation, after it verified.
#[wasm_bindgen]
pub struct PresentationResult {
  inner: crate::flow::PresentationResult,
}

#[wasm_bindgen]
impl PresentationResult {
  #[wasm_bindgen(getter)]
  pub fn vct(&self) -> String {
    self.inner.vct.clone()
  }

  /// The disclosed claims as a JSON object mapping RFC 6901 pointer to
  /// value — a plain `object`, not a class, so the page can index it
  /// directly.
  ///
  /// Withheld claims are absent, not null: a verifier learns nothing about
  /// them beyond their pointer appearing in the header's map.
  #[wasm_bindgen(getter)]
  pub fn disclosed(&self) -> Result<DisclosedClaims, JsValue> {
    let mut out = serde_json::Map::new();
    for claim in &self.inner.disclosed {
      let value: serde_json::Value =
        serde_json::from_str(&claim.value_json).map_err(|e| JsValue::from_str(&format!("disclosed claim is not valid JSON: {e}")))?;
      out.insert(claim.pointer.clone(), value);
    }
    // Through JSON.parse rather than a hand-built object: it is one call,
    // and it cannot disagree with what every other binding returns.
    Ok(js_sys::JSON::parse(&serde_json::Value::Object(out).to_string())?.unchecked_into())
  }
}

/// The holder's own claims, turned into the messages it commits to.
///
/// The wallet's first step in blind issuance. `claimsJson` is a JSON
/// object; the messages come back in the order the issuer will assign
/// indices in, with the pointers the credential request must carry.
#[wasm_bindgen(js_name = jwpCommittedMessages)]
pub fn jwp_committed_messages(claims_json: &str) -> Result<CommittedMessages, JsValue> {
  Ok(CommittedMessages {
    inner: crate::flow::committed_messages(claims_json).map_err(err)?,
  })
}

/// Read a stored credential without verifying it — for deciding whether it
/// can satisfy a request. Proves nothing about the signature; use
/// [`jwp_accept`] for that.
#[wasm_bindgen(js_name = jwpInspect)]
pub fn jwp_inspect(issued_jwp: &str) -> Result<CredentialInfo, JsValue> {
  Ok(CredentialInfo {
    inner: crate::flow::inspect(issued_jwp).map_err(err)?,
  })
}

/// Check a freshly issued credential before storing it. Not optional — it
/// is the holder's only chance to catch an issuer that signed something
/// other than what was asked for.
#[wasm_bindgen(js_name = jwpAccept)]
pub fn jwp_accept(
  suite_id: &str,
  issued_jwp: &str,
  issuer_public_key: &[u8],
  committed_messages: &js_sys::Array,
  keybind_public_keys: &js_sys::Array,
  secret_prover_blind: &[u8],
) -> Result<CredentialInfo, JsValue> {
  Ok(CredentialInfo {
    inner: crate::flow::accept(
      suite_id_for(suite_id)?,
      issued_jwp,
      issuer_public_key,
      &byte_arrays(committed_messages)?,
      &byte_arrays(keybind_public_keys)?,
      secret_prover_blind,
    )
    .map_err(err)?,
  })
}

/// Begin a presentation, disclosing exactly `requestedPointers`. Sign each
/// `keybindChallenges` entry on the main thread, then call
/// [`jwp_present_finalize`].
#[wasm_bindgen(js_name = jwpPresentInit)]
#[allow(clippy::too_many_arguments)]
pub fn jwp_present_init(
  suite_id: &str,
  issued_jwp: &str,
  issuer_public_key: &[u8],
  presentation_header: &[u8],
  requested_pointers: Vec<String>,
  committed_messages: &js_sys::Array,
  keybind_public_keys: &js_sys::Array,
  secret_prover_blind: &[u8],
) -> Result<PresentInit, JsValue> {
  Ok(PresentInit {
    inner: crate::flow::present_init(
      suite_id_for(suite_id)?,
      issued_jwp,
      issuer_public_key,
      presentation_header,
      &requested_pointers,
      &byte_arrays(committed_messages)?,
      &byte_arrays(keybind_public_keys)?,
      secret_prover_blind,
    )
    .map_err(err)?,
  })
}

/// Complete the presentation, returning the compact presented JWP.
#[wasm_bindgen(js_name = jwpPresentFinalize)]
pub fn jwp_present_finalize(suite_id: &str, state: &[u8], keybind_signatures: &js_sys::Array) -> Result<String, JsValue> {
  crate::flow::present_finalize(suite_id_for(suite_id)?, state, &byte_arrays(keybind_signatures)?).map_err(err)
}

/// Verify a presentation and return what it disclosed. Present mainly so a
/// wallet can check its own output; a real relying party verifies
/// server-side.
#[wasm_bindgen(js_name = jwpVerify)]
pub fn jwp_verify(suite_id: &str, presented_jwp: &str, issuer_public_key: &[u8]) -> Result<PresentationResult, JsValue> {
  Ok(PresentationResult {
    inner: crate::flow::verify(suite_id_for(suite_id)?, presented_jwp, issuer_public_key).map_err(err)?,
  })
}

/// Build a Presentation Header. `extraJson`, if given, is a JSON object
/// whose members are merged in — where a transport binds its own session
/// transcript.
#[wasm_bindgen(js_name = jwpBuildPresentationHeader)]
pub fn jwp_build_presentation_header(nonce: &str, aud: &str, extra_json: Option<String>) -> Result<Vec<u8>, JsValue> {
  crate::flow::build_presentation_header(nonce, aud, extra_json.as_deref()).map_err(err)
}
