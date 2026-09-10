// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! The credential-level flows, in plain Rust, shared by every binding.
//!
//! `blind.rs` operates on message vectors: it knows nothing about claims,
//! pointers, or containers. `jwp.rs` knows the container but performs no
//! cryptography. This module is the join — the seven operations a wallet
//! or a relying party actually calls, each one mapping claims to messages,
//! running the arithmetic, and mapping the result back.
//!
//! It exists as its own module because there are three bindings (UniFFI
//! for the native SDKs, the C ABI for Go, wasm-bindgen for the browser),
//! and this logic is the part where they can silently disagree. A copy per
//! binding would mean the browser wallet deciding message order one way
//! and the Kotlin wallet another, which does not fail at the boundary — it
//! fails much later, as a credential whose map names one claim while the
//! signature covers a different one. So the bindings own type conversion
//! and nothing else; every one of them calls these functions.
//!
//! Signatures here are deliberately binding-agnostic: borrowed slices,
//! [`crate::Error`], no `Option`-shaped conveniences that only one FFI
//! needs.

use crate::blind::{BlindSuite, Disclosure, PLAIN_SUITE_ID, SCHNORR_SUITE_ID};
use crate::error::{Error, Result};
use crate::keybind::SchnorrBls12381;
use crate::suite::{ScalarSource, Suite};

/// Which key binding construction, and therefore which domain separation,
/// a credential uses.
///
/// Not a binding-specific enum: the wire name is the same across all of
/// them, so parsing it is the same code too.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuiteId {
  /// Blind BBS with no device binding.
  Plain,
  /// Blind BBS with Schnorr-on-BLS12-381-G1 device binding — the profile
  /// in `PROFILE.md`.
  Schnorr,
}

impl SuiteId {
  /// The suite's identifier octets, as they appear in domain separation.
  pub fn as_str(self) -> &'static str {
    match self {
      SuiteId::Plain => PLAIN_SUITE_ID,
      SuiteId::Schnorr => SCHNORR_SUITE_ID,
    }
  }

  /// The short name a caller passes across a boundary that has no enums —
  /// the wasm API, and the `bbs_suite` member of a credential request.
  pub fn wire_name(self) -> &'static str {
    match self {
      SuiteId::Plain => "plain",
      SuiteId::Schnorr => "schnorr",
    }
  }

  /// Parse [`wire_name`](Self::wire_name).
  ///
  /// Unknown names are rejected rather than defaulted. Defaulting would
  /// mean a typo silently selecting a different domain separation, which
  /// produces a credential that verifies nowhere for no visible reason.
  pub fn parse(name: &str) -> Result<Self> {
    match name {
      "plain" => Ok(SuiteId::Plain),
      "schnorr" => Ok(SuiteId::Schnorr),
      _ => Err(Error::Unsupported("unknown suite: expected \"plain\" or \"schnorr\"")),
    }
  }
}

/// The suite instance every flow below runs on.
pub fn suite(id: SuiteId) -> BlindSuite<SchnorrBls12381> {
  BlindSuite::new(Suite::new(ScalarSource::System), SchnorrBls12381, id.as_str())
}

/// The holder's claims, as the messages it commits to.
pub struct CommittedMessages {
  /// The messages to hand to `commit_init`, in order.
  pub messages: Vec<Vec<u8>>,
  /// Their RFC 6901 pointers, in the same order.
  pub pointers: Vec<String>,
}

/// What a stored credential says about itself.
pub struct CredentialInfo {
  /// The SD-JWT VC type identifier.
  pub vct: String,
  /// The key binding identifier, absent if not bound to a device key.
  pub kb: Option<String>,
  /// Every claim's RFC 6901 pointer, in message order.
  pub pointers: Vec<String>,
  /// How many of the messages the issuer supplied; the rest are the
  /// holder's own.
  pub num_signer_messages: usize,
}

impl CredentialInfo {
  fn of(view: &crate::jwp::IssuerHeaderView) -> Self {
    Self {
      vct: view.vct.clone(),
      kb: view.kb.clone(),
      pointers: view.pointers(),
      num_signer_messages: view.num_signer_messages(),
    }
  }
}

/// One claim a verifier learned from a presentation.
pub struct DisclosedClaim {
  /// RFC 6901 pointer naming the claim.
  pub pointer: String,
  /// Its value, as JSON.
  pub value_json: String,
}

/// What a verifier learned from a presentation, after it verified.
pub struct PresentationResult {
  pub vct: String,
  /// Only the claims actually disclosed. Withheld ones are absent, not
  /// null.
  pub disclosed: Vec<DisclosedClaim>,
}

/// Output of [`present_init`].
pub struct PresentInit {
  /// Opaque state for [`present_finalize`].
  pub state: Vec<u8>,
  /// One already-hashed challenge per key binding key.
  pub keybind_challenges: Vec<Vec<u8>>,
}

/// The holder's own claims, turned into the messages it commits to.
///
/// The wallet's first step in blind issuance. It has claims by name and
/// needs the ordered octet strings `commit_init` takes, in the same order
/// the issuer will later assign message indices in — otherwise the
/// credential's map names one claim while the signature covers another.
///
/// Note what is NOT needed here: the issuer's message count. Indices go in
/// the header's map, which the issuer builds; the message octets are just
/// the claim values, so the wallet can commit before it knows how many
/// claims the issuer will add.
///
/// Returns the pointers alongside the messages because the credential
/// request must carry them — the issuer never sees these values and cannot
/// name them itself.
pub fn committed_messages(claims_json: &str) -> Result<CommittedMessages> {
  let claims: serde_json::Value = serde_json::from_str(claims_json).map_err(|e| Error::MalformedContainer(format!("claims are not valid JSON: {e}")))?;
  let (_, messages, pointers) = crate::jwp::build_cmap(&claims, 0)?;
  Ok(CommittedMessages { messages, pointers })
}

/// Read a stored credential without verifying it.
///
/// For deciding whether this credential can satisfy a request. It parses
/// and structurally validates the container, but proves nothing about the
/// signature — use [`accept`] for that.
pub fn inspect(issued_jwp: &str) -> Result<CredentialInfo> {
  let issued = crate::jwp::IssuedJwp::decode(issued_jwp)?;
  Ok(CredentialInfo::of(&issued.header()?))
}

/// Check a freshly issued credential before storing it.
///
/// This is not optional. It is the holder's only chance to find out that
/// the issuer signed something other than what was asked for, or that the
/// credential is not actually bound to the device key that was committed —
/// both of which otherwise surface much later, as a presentation that will
/// not verify.
pub fn accept(
  suite_id: SuiteId,
  issued_jwp: &str,
  issuer_public_key: &[u8],
  committed: &[Vec<u8>],
  keybind_public_keys: &[Vec<u8>],
  secret_prover_blind: &[u8],
) -> Result<CredentialInfo> {
  let issued = crate::jwp::IssuedJwp::decode(issued_jwp)?;
  let view = issued.header()?;
  let blind = crate::bbs::scalar_from_be(secret_prover_blind)?;
  let messages = all_messages(&issued, &view, committed)?;

  suite(suite_id).verify_blind_sign(
    issuer_public_key,
    &issued.signature,
    &issued.issuer_header,
    &messages,
    view.num_signer_messages(),
    keybind_public_keys,
    &blind,
  )?;

  Ok(CredentialInfo::of(&view))
}

/// Begin a presentation, disclosing exactly `requested_pointers`.
///
/// Splits around the authenticator signature for the same reason
/// `blind_proof_gen_init` does: the device signs in the middle, and on the
/// web that happens on a different thread than the computation.
#[allow(clippy::too_many_arguments)]
pub fn present_init(
  suite_id: SuiteId,
  issued_jwp: &str,
  issuer_public_key: &[u8],
  presentation_header: &[u8],
  requested_pointers: &[String],
  committed: &[Vec<u8>],
  keybind_public_keys: &[Vec<u8>],
  secret_prover_blind: &[u8],
) -> Result<PresentInit> {
  let issued = crate::jwp::IssuedJwp::decode(issued_jwp)?;
  let view = issued.header()?;
  let blind = crate::bbs::scalar_from_be(secret_prover_blind)?;
  let messages = all_messages(&issued, &view, committed)?;

  let disclosures = crate::jwp::disclosures_for(&view, requested_pointers)?;
  let (state, _committed, keybind_challenges) = suite(suite_id).blind_proof_gen_init(
    issuer_public_key,
    &issued.signature,
    &issued.issuer_header,
    presentation_header,
    &messages,
    view.num_signer_messages(),
    &disclosures,
    keybind_public_keys,
    &blind,
  )?;

  // The presented container is assembled in `finalize`, so everything it
  // needs travels in the state rather than being recomputed there from
  // inputs the caller would have to pass twice - and get identical twice.
  let carried = PresentCarry {
    inner: state,
    presentation_header: presentation_header.to_vec(),
    issuer_header: issued.issuer_header,
    payloads: messages
      .iter()
      .zip(&disclosures)
      .map(|(m, d)| if *d == Disclosure::Disclose { Some(m.clone()) } else { None })
      .collect(),
  };
  Ok(PresentInit {
    state: carried.encode(),
    keybind_challenges,
  })
}

/// Complete the presentation, returning the compact presented JWP.
pub fn present_finalize(suite_id: SuiteId, state: &[u8], keybind_signatures: &[Vec<u8>]) -> Result<String> {
  let carried = PresentCarry::decode(state)?;
  let proof = suite(suite_id).blind_proof_gen_finalize(&carried.inner, keybind_signatures)?;
  Ok(
    crate::jwp::PresentedJwp {
      presentation_header: carried.presentation_header,
      issuer_header: carried.issuer_header,
      payloads: carried.payloads,
      proof,
    }
    .encode(),
  )
}

/// Verify a presentation and return what it disclosed.
///
/// A wallet uses this to check its own output; a relying party uses it as
/// its whole implementation. The important property is that it is the same
/// code either way.
pub fn verify(suite_id: SuiteId, presented_jwp: &str, issuer_public_key: &[u8]) -> Result<PresentationResult> {
  let presented = crate::jwp::PresentedJwp::decode(presented_jwp)?;
  let view = presented.header()?;
  let disclosures = presented.disclosures();

  suite(suite_id).blind_proof_verify(
    issuer_public_key,
    &presented.proof,
    &presented.issuer_header,
    &presented.presentation_header,
    view.num_signer_messages(),
    &presented.disclosed_messages(),
    &disclosures,
  )?;

  // Only reached once the proof verified, so every pointer/value pair here
  // is one the issuer actually signed.
  let pointers = view.pointers();
  let mut disclosed = Vec::new();
  for (index, payload) in presented.payloads.iter().enumerate() {
    if let Some(bytes) = payload {
      disclosed.push(DisclosedClaim {
        pointer: pointers[index].clone(),
        value_json: String::from_utf8(bytes.clone()).map_err(|_| Error::MalformedContainer("a disclosed claim is not valid UTF-8".into()))?,
      });
    }
  }
  Ok(PresentationResult {
    vct: view.vct.clone(),
    disclosed,
  })
}

/// Build a Presentation Header.
///
/// `extra_json`, if given, is a JSON object whose members are merged in —
/// the profile needs somewhere to bind a transport's own session
/// transcript, and which member that is belongs to the SDK, not here.
pub fn build_presentation_header(nonce: &str, aud: &str, extra_json: Option<&str>) -> Result<Vec<u8>> {
  let extra = match extra_json {
    None => serde_json::Map::new(),
    Some(raw) => serde_json::from_str::<serde_json::Value>(raw)
      .map_err(|e| Error::MalformedContainer(format!("extra header parameters are not valid JSON: {e}")))?
      .as_object()
      .cloned()
      .ok_or_else(|| Error::MalformedContainer("extra header parameters are not a JSON object".into()))?,
  };
  crate::jwp::build_presentation_header(nonce, aud, &extra)
}

/// The issuer's payloads followed by the holder's committed messages —
/// the full vector, in the order the signature covers.
///
/// Checked against the header's own count here rather than being left to
/// fail inside the arithmetic, where the error would name a generator
/// count instead of the actual mistake: the caller supplied the wrong
/// committed messages for this credential.
fn all_messages(issued: &crate::jwp::IssuedJwp, view: &crate::jwp::IssuerHeaderView, committed: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
  let mut messages = issued.payloads.clone();
  messages.extend_from_slice(committed);
  if messages.len() != view.num_messages() {
    return Err(Error::MalformedContainer(format!(
      "credential maps {} messages but {} were supplied",
      view.num_messages(),
      messages.len()
    )));
  }
  Ok(messages)
}

/// Everything `present_finalize` needs that `present_init` already had.
///
/// A length-prefixed encoding rather than JSON or a serde derive: it
/// crosses a worker boundary as a `Uint8Array`, and it must round-trip
/// byte-exactly, since the payloads it carries are the octets the
/// signature covers.
struct PresentCarry {
  inner: Vec<u8>,
  presentation_header: Vec<u8>,
  issuer_header: Vec<u8>,
  payloads: Vec<Option<Vec<u8>>>,
}

impl PresentCarry {
  fn encode(&self) -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |b: &[u8]| {
      out.extend_from_slice(&(b.len() as u32).to_be_bytes());
      out.extend_from_slice(b);
    };
    put(&self.inner);
    put(&self.presentation_header);
    put(&self.issuer_header);
    out.extend_from_slice(&(self.payloads.len() as u32).to_be_bytes());
    for p in &self.payloads {
      match p {
        // A withheld slot and a present-but-empty one must stay
        // distinguishable here too, so the tag is not the length.
        None => out.push(0),
        Some(b) => {
          out.push(1);
          out.extend_from_slice(&(b.len() as u32).to_be_bytes());
          out.extend_from_slice(b);
        }
      }
    }
    out
  }

  fn decode(data: &[u8]) -> Result<Self> {
    let mut cur = Cursor { data, pos: 0 };
    let inner = cur.blob()?;
    let presentation_header = cur.blob()?;
    let issuer_header = cur.blob()?;
    let count = cur.length()?;
    if count > crate::jwp::MAX_MESSAGES {
      return Err(Error::MalformedContainer(format!(
        "presentation state claims {count} payload slots, over the limit"
      )));
    }
    let mut payloads = Vec::with_capacity(count);
    for _ in 0..count {
      match cur.take(1)?[0] {
        0 => payloads.push(None),
        1 => payloads.push(Some(cur.blob()?)),
        other => return Err(Error::MalformedContainer(format!("presentation state has an unknown payload tag {other}"))),
      }
    }
    if cur.pos != data.len() {
      return Err(Error::MalformedContainer("presentation state has trailing content".into()));
    }
    Ok(Self {
      inner,
      presentation_header,
      issuer_header,
      payloads,
    })
  }
}

struct Cursor<'a> {
  data: &'a [u8],
  pos: usize,
}

impl<'a> Cursor<'a> {
  fn take(&mut self, n: usize) -> Result<&'a [u8]> {
    let end = self
      .pos
      .checked_add(n)
      .filter(|e| *e <= self.data.len())
      .ok_or_else(|| Error::MalformedContainer("presentation state is truncated".into()))?;
    let out = &self.data[self.pos..end];
    self.pos = end;
    Ok(out)
  }

  fn length(&mut self) -> Result<usize> {
    let b: [u8; 4] = self.take(4)?.try_into().expect("take(4) yields 4 octets");
    Ok(u32::from_be_bytes(b) as usize)
  }

  fn blob(&mut self) -> Result<Vec<u8>> {
    let n = self.length()?;
    Ok(self.take(n)?.to_vec())
  }
}
