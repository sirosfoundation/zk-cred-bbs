// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
//! The credential container: a profile of JWP.
//!
//! [`crate::blind`] signs and proves over an ordered list of opaque octet
//! strings. A credential is a set of *named claims*. This module is the
//! mapping between the two, plus the wire format that carries it.
//!
//! # What this implements, and what it does not
//!
//! The container is the Compact Serialization of JWP
//! (`draft-ietf-jose-json-web-proof-13` §7.1), and the credential shape
//! follows `draft-bormann-jwp-modular-bbs-02`. It is a *profile* of those,
//! not a general implementation of either: it carries exactly the
//! construction this crate implements, and rejects everything else rather
//! than half-supporting it. Three deliberate divergences, each of which
//! would otherwise be a silent interop failure:
//!
//! 1. **Key binding is not `ecdsa-p256-db`.** The draft's device binding
//!    reserves four message slots for the device public key's coordinates
//!    as 128-bit limbs. This profile's key binding lives in the *issuance
//!    commitment*, with dedicated `KEYBIND_` generators, and its proof is
//!    inside the core proof rather than a sub-proof. So no slots are
//!    reserved (`N = 0`), and `kb` carries the private value
//!    [`KB_SCHNORR`]. See `PROFILE.md` §4.
//!
//! 2. **Blind-issuance messages need a home in the map.** The draft's
//!    `cmap` covers issuer payloads. Blind BBS also signs messages the
//!    issuer never saw, which have no Issuer Payload to be named by, so
//!    this profile adds [`HCMAP`] for them - same `[index, scalar]` leaf
//!    shape, disjoint index range. The names are not secret; only the
//!    values are.
//!
//! 3. **`scalar: true` is rejected.** The draft allows a claim to be
//!    carried as a raw scalar field element rather than a hashed octet
//!    string. This crate's message encoding always hashes, so accepting
//!    the flag would produce a credential whose messages do not match what
//!    the flag promises.
//!
//! Sub-proofs (range proofs, equality proofs) are not implemented. The
//! presented proof therefore always has exactly one octet string.
//!
//! # Why the header octets are kept verbatim
//!
//! The Issuer Header is the BBS `header` input, so the signature covers
//! its exact bytes. A holder that parsed the header and re-serialized it
//! before presenting would produce a different byte string whenever key
//! order or spacing differed - and BBS would then verify against the wrong
//! header and simply fail, with nothing in the failure pointing at
//! serialization. So [`IssuedJwp`] stores the decoded octets and never
//! rebuilds them; the parsed view is read-only.

use crate::blind::Disclosure;
use crate::error::{Error, Result};

use serde_json::{Map, Value};

/// The JWP algorithm identifier, required in both headers.
pub const ALG: &str = "BBS-MOD";

/// This profile's `kb` value.
///
/// Private, and deliberately not a draft-registered identifier: the
/// construction it names is pre-standardisation. A verifier that does not
/// recognise it must refuse the credential rather than fall back to the
/// draft's own device binding, which is a different message layout - see
/// the module docs.
pub const KB_SCHNORR: &str = "schnorr-bls12381g1-commit-v0";

/// Header parameter naming the blind-issuance (holder-committed) claims.
///
/// Divergence 2 in the module docs. Same leaf shape as `cmap`.
pub const HCMAP: &str = "hcmap";

/// Bounds the message vector.
///
/// Not a protocol limit - a guard. Message count drives generator
/// derivation and proof size, and it comes from whoever wrote the
/// credential, so an unbounded map would let a remote party dictate how
/// much work a verifier does before anything is authenticated.
pub const MAX_MESSAGES: usize = 512;

/// How one claim's value becomes one BBS message.
///
/// The message octets are the claim's JSON serialization. `blind`'s own
/// `messages_to_scalars` then hashes them, which is the draft's
/// `scalar: false` case; `scalar: true` is rejected on parse.
fn message_octets(value: &Value) -> Result<Vec<u8>> {
  serde_json::to_vec(value).map_err(|e| Error::MalformedContainer(format!("encoding claim value: {e}")))
}

/// A claim's position in the message vector, resolved from a `cmap` leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimIndex {
  /// RFC 6901 pointer to the claim within the credential's claim tree.
  pub pointer: String,
  /// Its index in the BBS message vector.
  pub index: usize,
}

/// Walks a `cmap`/`hcmap` tree, collecting `[index, scalar]` leaves
/// against their RFC 6901 pointers.
///
/// The escaping matters: without it a claim literally named `a/b` would be
/// indistinguishable from a nested `a` containing `b`, and a holder could
/// disclose one while a verifier believed it had seen the other.
fn walk_cmap(prefix: &str, value: &Value, out: &mut Vec<ClaimIndex>) -> Result<()> {
  match value {
    // A leaf: the two-element [index, scalar] annotation.
    Value::Array(items) if items.len() == 2 && items[0].is_number() => {
      let index = items[0]
        .as_u64()
        .ok_or_else(|| Error::MalformedContainer(format!("cmap index at {prefix} is not a non-negative integer")))?;
      let scalar = items[1]
        .as_bool()
        .ok_or_else(|| Error::MalformedContainer(format!("cmap scalar flag at {prefix} is not a boolean")))?;
      if scalar {
        return Err(Error::MalformedContainer(format!(
          "cmap entry at {prefix} requests scalar encoding, which this profile does not implement"
        )));
      }
      if index as usize >= MAX_MESSAGES {
        return Err(Error::MalformedContainer(format!(
          "cmap index {index} at {prefix} is over the {MAX_MESSAGES} limit"
        )));
      }
      out.push(ClaimIndex {
        pointer: if prefix.is_empty() { "/".to_string() } else { prefix.to_string() },
        index: index as usize,
      });
      Ok(())
    }
    Value::Object(map) => {
      for (k, child) in map {
        let escaped = k.replace('~', "~0").replace('/', "~1");
        walk_cmap(&format!("{prefix}/{escaped}"), child, out)?;
      }
      Ok(())
    }
    other => Err(Error::MalformedContainer(format!(
      "cmap entry at {} is neither an object nor an [index, scalar] leaf: {other}",
      if prefix.is_empty() { "/" } else { prefix }
    ))),
  }
}

/// The read-only view of an Issuer Header.
///
/// Read-only on purpose - see the module docs on why the octets are never
/// rebuilt from this.
#[derive(Debug, Clone)]
pub struct IssuerHeaderView {
  /// The SD-JWT VC credential type.
  pub vct: String,
  /// The key binding identifier, if the credential is bound to a device
  /// key. This profile only ever writes [`KB_SCHNORR`].
  pub kb: Option<String>,
  /// Issuer-known claims, sorted by message index.
  pub issuer_claims: Vec<ClaimIndex>,
  /// Holder-committed claims, sorted by message index.
  pub holder_claims: Vec<ClaimIndex>,
}

impl IssuerHeaderView {
  /// Total message-vector length.
  pub fn num_messages(&self) -> usize {
    self.issuer_claims.len() + self.holder_claims.len()
  }

  /// How many of the messages the issuer supplied.
  ///
  /// This is `blind`'s `num_signer_messages`, and it is a boundary, not a
  /// count of anything the holder chooses - the two halves of the message
  /// vector are signed differently.
  pub fn num_signer_messages(&self) -> usize {
    self.issuer_claims.len()
  }

  /// Resolves a claim pointer to its message index.
  pub fn index_of(&self, pointer: &str) -> Option<usize> {
    self
      .issuer_claims
      .iter()
      .chain(self.holder_claims.iter())
      .find(|c| c.pointer == pointer)
      .map(|c| c.index)
  }

  /// Every claim pointer, in message order.
  pub fn pointers(&self) -> Vec<String> {
    let mut all: Vec<&ClaimIndex> = self.issuer_claims.iter().chain(self.holder_claims.iter()).collect();
    all.sort_by_key(|c| c.index);
    all.into_iter().map(|c| c.pointer.clone()).collect()
  }

  /// Parses and validates an Issuer Header from its exact octets.
  ///
  /// Validation here is what stops a malformed map reaching the algebra,
  /// where an index gap or duplicate would surface as an unhelpful
  /// length mismatch - or, worse, as a proof over a message vector that
  /// does not mean what the map says it means.
  pub fn parse(octets: &[u8]) -> Result<Self> {
    let header: Value = serde_json::from_slice(octets).map_err(|e| Error::MalformedContainer(format!("issuer header is not valid JSON: {e}")))?;
    let obj = header
      .as_object()
      .ok_or_else(|| Error::MalformedContainer("issuer header is not a JSON object".into()))?;

    match obj.get("alg").and_then(Value::as_str) {
      Some(ALG) => {}
      Some(other) => return Err(Error::MalformedContainer(format!("issuer header alg is {other:?}, expected {ALG:?}"))),
      None => return Err(Error::MalformedContainer("issuer header has no alg".into())),
    }

    let vct = obj
      .get("vct")
      .and_then(Value::as_str)
      .ok_or_else(|| Error::MalformedContainer("issuer header has no vct".into()))?
      .to_string();

    let kb = obj.get("kb").and_then(Value::as_str).map(str::to_string);
    if let Some(kb) = &kb
      && kb != KB_SCHNORR
    {
      return Err(Error::MalformedContainer(format!(
        "issuer header kb is {kb:?}; this profile implements only {KB_SCHNORR:?}"
      )));
    }

    let mut issuer_claims = Vec::new();
    let cmap = obj.get("cmap").ok_or_else(|| Error::MalformedContainer("issuer header has no cmap".into()))?;
    walk_cmap("", cmap, &mut issuer_claims)?;

    let mut holder_claims = Vec::new();
    if let Some(hcmap) = obj.get(HCMAP) {
      walk_cmap("", hcmap, &mut holder_claims)?;
    }

    issuer_claims.sort_by_key(|a| a.index);
    holder_claims.sort_by_key(|a| a.index);

    let view = IssuerHeaderView {
      vct,
      kb,
      issuer_claims,
      holder_claims,
    };

    // The two maps must together cover 0..n exactly once. A gap would
    // leave a message no claim names; an overlap would let two claims
    // name the same message, so disclosing one would disclose the
    // other.
    let mut seen: Vec<usize> = view.issuer_claims.iter().chain(view.holder_claims.iter()).map(|c| c.index).collect();
    seen.sort_unstable();
    if seen.is_empty() {
      return Err(Error::MalformedContainer("issuer header maps no claims".into()));
    }
    if seen.len() > MAX_MESSAGES {
      return Err(Error::MalformedContainer(format!(
        "issuer header maps {} claims, over the {MAX_MESSAGES} limit",
        seen.len()
      )));
    }
    for (expected, got) in seen.iter().enumerate() {
      if expected != *got {
        return Err(Error::MalformedContainer(format!(
          "issuer header claim indices are not 0..{} without gaps or duplicates (index {got} where {expected} was expected)",
          seen.len()
        )));
      }
    }
    // Issuer messages must be the LOW half. blind's own
    // `num_signer_messages` is a split point, not a set membership
    // test, so an interleaved map would silently sign holder messages
    // as issuer ones.
    for claim in &view.issuer_claims {
      if claim.index >= view.num_signer_messages() {
        return Err(Error::MalformedContainer(format!(
          "issuer claim {} has index {} at or above the signer/holder split at {}",
          claim.pointer,
          claim.index,
          view.num_signer_messages()
        )));
      }
    }
    Ok(view)
  }
}

/// Assigns message indices to the leaves of a claims document, producing a
/// `cmap` and the matching message octets.
///
/// Indices are assigned in sorted-pointer order so that the same claims
/// always produce the same map. Empty objects and arrays are leaves in
/// their own right: dropping them would make `{"a":{}}` and `{}` sign
/// identically.
pub fn build_cmap(claims: &Value, first_index: usize) -> Result<(Value, Vec<Vec<u8>>, Vec<String>)> {
  let obj = claims
    .as_object()
    .ok_or_else(|| Error::MalformedContainer("claims must be a JSON object".into()))?;
  if obj.is_empty() {
    return Err(Error::MalformedContainer("claims contain no values to sign".into()));
  }

  let mut leaves: Vec<(String, Value)> = Vec::new();
  collect_leaves("", claims, &mut leaves);
  leaves.sort_by(|a, b| a.0.cmp(&b.0));

  if leaves.len() > MAX_MESSAGES {
    return Err(Error::MalformedContainer(format!(
      "claims contain {} values, over the {MAX_MESSAGES} limit",
      leaves.len()
    )));
  }

  let mut cmap = Value::Object(Map::new());
  let mut messages = Vec::with_capacity(leaves.len());
  let mut pointers = Vec::with_capacity(leaves.len());
  for (i, (pointer, value)) in leaves.iter().enumerate() {
    let index = first_index + i;
    insert_at_pointer(&mut cmap, pointer, Value::Array(vec![index.into(), Value::Bool(false)]))?;
    messages.push(message_octets(value)?);
    pointers.push(pointer.clone());
  }
  Ok((cmap, messages, pointers))
}

/// Builds a map from claim *pointers* alone, with no values.
///
/// The issuer's side of blind issuance. It never sees the holder's
/// committed values - that is the point - but it must still place them in
/// the message vector, and both sides must agree on where.
///
/// Agreement rests on both sides sorting by pointer, exactly as
/// [`build_cmap`] does when the holder derives its committed messages from
/// the values. Get this wrong and every proof fails with nothing pointing
/// at the cause, so the ordering is not left to the caller's list order.
pub fn build_cmap_from_pointers(pointers: &[String], first_index: usize) -> Result<Value> {
  if pointers.is_empty() {
    return Err(Error::MalformedContainer("no claim pointers were supplied".into()));
  }
  if pointers.len() > MAX_MESSAGES {
    return Err(Error::MalformedContainer(format!(
      "{} claim pointers, over the {MAX_MESSAGES} limit",
      pointers.len()
    )));
  }
  let mut sorted: Vec<&String> = pointers.iter().collect();
  sorted.sort();
  for pair in sorted.windows(2) {
    if pair[0] == pair[1] {
      return Err(Error::MalformedContainer(format!("claim pointer {} appears twice", pair[0])));
    }
  }

  let mut cmap = Value::Object(Map::new());
  for (i, pointer) in sorted.iter().enumerate() {
    if !pointer.starts_with('/') && pointer.as_str() != "/" {
      return Err(Error::MalformedContainer(format!(
        "claim pointer {pointer} is not an RFC 6901 pointer (it must start with '/')"
      )));
    }
    insert_at_pointer(&mut cmap, pointer, Value::Array(vec![(first_index + i).into(), Value::Bool(false)]))?;
  }
  Ok(cmap)
}

fn collect_leaves(prefix: &str, value: &Value, out: &mut Vec<(String, Value)>) {
  let pointer = || if prefix.is_empty() { "/".to_string() } else { prefix.to_string() };
  match value {
    Value::Object(map) if !map.is_empty() => {
      for (k, child) in map {
        let escaped = k.replace('~', "~0").replace('/', "~1");
        collect_leaves(&format!("{prefix}/{escaped}"), child, out);
      }
    }
    Value::Array(items) if !items.is_empty() => {
      for (i, child) in items.iter().enumerate() {
        collect_leaves(&format!("{prefix}/{i}"), child, out);
      }
    }
    leaf => out.push((pointer(), leaf.clone())),
  }
}

/// Rebuilds the claim tree's shape in the cmap, placing `leaf` at
/// `pointer`. Arrays in the claim tree become objects with decimal keys in
/// the cmap - the draft's own shape, and unambiguous because a cmap leaf is
/// always a two-element array.
fn insert_at_pointer(root: &mut Value, pointer: &str, leaf: Value) -> Result<()> {
  if pointer == "/" {
    *root = leaf;
    return Ok(());
  }
  let parts: Vec<&str> = pointer.trim_start_matches('/').split('/').collect();
  let mut node = root;
  for (i, part) in parts.iter().enumerate() {
    let key = part.replace("~1", "/").replace("~0", "~");
    let key = key.replace('~', "~0").replace('/', "~1");
    let map = node
      .as_object_mut()
      .ok_or_else(|| Error::MalformedContainer(format!("cmap shape conflict at {pointer}")))?;
    if i == parts.len() - 1 {
      map.insert(key, leaf);
      return Ok(());
    }
    node = map.entry(key).or_insert_with(|| Value::Object(Map::new()));
  }
  Ok(())
}

// ---------------------------------------------------------------------------
// Compact Serialization (draft-ietf-jose-json-web-proof-13 §7.1)
// ---------------------------------------------------------------------------

/// base64url without padding, per RFC 4648 §5.
fn b64_encode(data: &[u8]) -> String {
  const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
  for chunk in data.chunks(3) {
    let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
    let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
    let idx = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
    // A 1-byte chunk yields 2 characters, a 2-byte chunk 3 - unpadded
    // base64url emits only the characters the input actually fills.
    for &v in idx.iter().take(chunk.len() + 1) {
      out.push(ALPHABET[v as usize] as char);
    }
  }
  out
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
  fn val(c: u8) -> Option<u8> {
    Some(match c {
      b'A'..=b'Z' => c - b'A',
      b'a'..=b'z' => c - b'a' + 26,
      b'0'..=b'9' => c - b'0' + 52,
      b'-' => 62,
      b'_' => 63,
      _ => return None,
    })
  }
  let bytes = s.as_bytes();
  if bytes.len() % 4 == 1 {
    return Err(Error::MalformedContainer("invalid base64url length".into()));
  }
  let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
  for chunk in bytes.chunks(4) {
    let mut n: u32 = 0;
    for (i, &c) in chunk.iter().enumerate() {
      let v = val(c).ok_or_else(|| Error::MalformedContainer("invalid base64url character".into()))?;
      n |= u32::from(v) << (18 - 6 * i);
    }
    for i in 0..chunk.len() - 1 {
      out.push((n >> (16 - 8 * i)) as u8);
    }
  }
  Ok(out)
}

/// Encodes one `~`-separated group. `None` is an omitted payload; an empty
/// octet string is `_`, so that "omitted" and "present but empty" stay
/// distinguishable (§7.1).
fn encode_group(values: &[Option<Vec<u8>>]) -> String {
  values
    .iter()
    .map(|v| match v {
      None => String::new(),
      Some(b) if b.is_empty() => "_".to_string(),
      Some(b) => b64_encode(b),
    })
    .collect::<Vec<_>>()
    .join("~")
}

fn decode_group(s: &str) -> Result<Vec<Option<Vec<u8>>>> {
  s.split('~')
    .map(|part| match part {
      "" => Ok(None),
      "_" => Ok(Some(Vec::new())),
      other => b64_decode(other).map(Some),
    })
    .collect()
}

/// A credential as issued: three dot-separated parts.
#[derive(Debug, Clone)]
pub struct IssuedJwp {
  /// The Issuer Header's exact octets - the BBS `header` input.
  pub issuer_header: Vec<u8>,
  /// One payload per issuer-known message, in message order. All present.
  pub payloads: Vec<Vec<u8>>,
  /// The blind BBS signature.
  pub signature: Vec<u8>,
}

impl IssuedJwp {
  /// `header . payloads . proof`
  pub fn encode(&self) -> String {
    let payloads: Vec<Option<Vec<u8>>> = self.payloads.iter().cloned().map(Some).collect();
    format!(
      "{}.{}.{}",
      b64_encode(&self.issuer_header),
      encode_group(&payloads),
      encode_group(&[Some(self.signature.clone())]),
    )
  }

  pub fn decode(s: &str) -> Result<Self> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
      return Err(Error::MalformedContainer(format!(
        "an issued JWP has 3 dot-separated parts, got {}",
        parts.len()
      )));
    }
    let issuer_header = b64_decode(parts[0])?;
    let payloads = decode_group(parts[1])?
      .into_iter()
      .map(|p| p.ok_or_else(|| Error::MalformedContainer("an issued JWP cannot omit a payload".into())))
      .collect::<Result<Vec<_>>>()?;
    let proof = decode_group(parts[2])?;
    if proof.len() != 1 {
      return Err(Error::MalformedContainer(format!(
        "this profile's issued proof is one octet string, got {}",
        proof.len()
      )));
    }
    let signature = proof
      .into_iter()
      .next()
      .unwrap()
      .ok_or_else(|| Error::MalformedContainer("issued proof is empty".into()))?;
    Ok(Self {
      issuer_header,
      payloads,
      signature,
    })
  }

  /// Parses and validates the header.
  pub fn header(&self) -> Result<IssuerHeaderView> {
    let view = IssuerHeaderView::parse(&self.issuer_header)?;
    if view.num_signer_messages() != self.payloads.len() {
      return Err(Error::MalformedContainer(format!(
        "issuer header maps {} issuer claims but the JWP carries {} payloads",
        view.num_signer_messages(),
        self.payloads.len()
      )));
    }
    Ok(view)
  }
}

/// A credential as presented: four dot-separated parts, presentation
/// header first (§7.1).
#[derive(Debug, Clone)]
pub struct PresentedJwp {
  /// The Presentation Header's exact octets - the BBS
  /// `presentation_header` input.
  pub presentation_header: Vec<u8>,
  /// The Issuer Header, byte-identical to the issued form's.
  pub issuer_header: Vec<u8>,
  /// One slot per message, `None` where undisclosed. Holder-committed
  /// messages occupy the tail slots and may be disclosed like any other.
  pub payloads: Vec<Option<Vec<u8>>>,
  /// The core proof. Sub-proofs are not implemented, so this is the only
  /// octet string.
  pub proof: Vec<u8>,
}

impl PresentedJwp {
  pub fn encode(&self) -> String {
    format!(
      "{}.{}.{}.{}",
      b64_encode(&self.presentation_header),
      b64_encode(&self.issuer_header),
      encode_group(&self.payloads),
      encode_group(&[Some(self.proof.clone())]),
    )
  }

  pub fn decode(s: &str) -> Result<Self> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
      return Err(Error::MalformedContainer(format!(
        "a presented JWP has 4 dot-separated parts, got {}",
        parts.len()
      )));
    }
    let presentation_header = b64_decode(parts[0])?;
    let issuer_header = b64_decode(parts[1])?;
    let payloads = decode_group(parts[2])?;
    let proof = decode_group(parts[3])?;
    if proof.len() != 1 {
      return Err(Error::MalformedContainer(format!(
        "this profile's presented proof is one octet string, got {} - sub-proofs are not implemented",
        proof.len()
      )));
    }
    let proof = proof
      .into_iter()
      .next()
      .unwrap()
      .ok_or_else(|| Error::MalformedContainer("presented proof is empty".into()))?;
    Ok(Self {
      presentation_header,
      issuer_header,
      payloads,
      proof,
    })
  }

  /// The disclosure vector this presentation's payload slots describe.
  ///
  /// Derived from the slots rather than carried separately: the two must
  /// agree, and a single source cannot disagree with itself.
  pub fn disclosures(&self) -> Vec<Disclosure> {
    self
      .payloads
      .iter()
      .map(|p| if p.is_some() { Disclosure::Disclose } else { Disclosure::Hide })
      .collect()
  }

  /// The disclosed messages, in message order, as the verifier needs them.
  pub fn disclosed_messages(&self) -> Vec<Vec<u8>> {
    self.payloads.iter().flatten().cloned().collect()
  }

  /// Parses and validates both headers against each other.
  pub fn header(&self) -> Result<IssuerHeaderView> {
    let view = IssuerHeaderView::parse(&self.issuer_header)?;
    if view.num_messages() != self.payloads.len() {
      return Err(Error::MalformedContainer(format!(
        "issuer header maps {} messages but the presentation carries {} payload slots",
        view.num_messages(),
        self.payloads.len()
      )));
    }
    let ph: Value =
      serde_json::from_slice(&self.presentation_header).map_err(|e| Error::MalformedContainer(format!("presentation header is not valid JSON: {e}")))?;
    let obj = ph
      .as_object()
      .ok_or_else(|| Error::MalformedContainer("presentation header is not a JSON object".into()))?;
    // Both headers carry alg, and the draft requires them to agree. If
    // they were allowed to differ, the presentation header - which the
    // verifier supplies inputs to - could name a different algorithm
    // than the one the signature was made under.
    match obj.get("alg").and_then(Value::as_str) {
      Some(ALG) => {}
      Some(other) => return Err(Error::MalformedContainer(format!("presentation header alg is {other:?}, expected {ALG:?}"))),
      None => return Err(Error::MalformedContainer("presentation header has no alg".into())),
    }
    if obj.get("nonce").and_then(Value::as_str).is_none() {
      return Err(Error::MalformedContainer("presentation header has no nonce".into()));
    }
    if obj.get("aud").and_then(Value::as_str).is_none() {
      return Err(Error::MalformedContainer("presentation header has no aud".into()));
    }
    Ok(view)
  }
}

/// Builds an Issuer Header's octets.
///
/// Returns the serialized bytes, which from here on are the credential's
/// identity as far as BBS is concerned and must not be regenerated.
pub fn build_issuer_header(vct: &str, cmap: Value, hcmap: Option<Value>, kb: Option<&str>, extra: &Map<String, Value>) -> Result<Vec<u8>> {
  let mut obj = Map::new();
  obj.insert("alg".into(), Value::String(ALG.into()));
  obj.insert("vct".into(), Value::String(vct.into()));
  if let Some(kb) = kb {
    obj.insert("kb".into(), Value::String(kb.into()));
  }
  obj.insert("cmap".into(), cmap);
  if let Some(hcmap) = hcmap {
    obj.insert(HCMAP.into(), hcmap);
  }
  for (k, v) in extra {
    // Reserved names are built above from validated inputs; letting a
    // caller's extras overwrite them would let `extra` smuggle in a
    // different alg or map than the one just validated.
    if matches!(k.as_str(), "alg" | "vct" | "kb" | "cmap" | HCMAP) {
      return Err(Error::MalformedContainer(format!("extra header parameter {k:?} is reserved")));
    }
    obj.insert(k.clone(), v.clone());
  }
  serde_json::to_vec(&Value::Object(obj)).map_err(|e| Error::MalformedContainer(format!("encoding issuer header: {e}")))
}

/// Builds a Presentation Header's octets.
pub fn build_presentation_header(nonce: &str, aud: &str, extra: &Map<String, Value>) -> Result<Vec<u8>> {
  let mut obj = Map::new();
  obj.insert("alg".into(), Value::String(ALG.into()));
  obj.insert("nonce".into(), Value::String(nonce.into()));
  obj.insert("aud".into(), Value::String(aud.into()));
  for (k, v) in extra {
    if matches!(k.as_str(), "alg" | "nonce" | "aud") {
      return Err(Error::MalformedContainer(format!("extra header parameter {k:?} is reserved")));
    }
    obj.insert(k.clone(), v.clone());
  }
  serde_json::to_vec(&Value::Object(obj)).map_err(|e| Error::MalformedContainer(format!("encoding presentation header: {e}")))
}

/// Turns a set of requested claim pointers into the disclosure vector
/// `blind` takes.
///
/// Unknown pointers are an error rather than a silent omission: a verifier
/// that asked for a claim this credential does not have should be told, not
/// handed a proof that quietly lacks it.
pub fn disclosures_for(view: &IssuerHeaderView, requested: &[String]) -> Result<Vec<Disclosure>> {
  let mut disclosures = vec![Disclosure::Hide; view.num_messages()];
  for pointer in requested {
    let index = view
      .index_of(pointer)
      .ok_or_else(|| Error::MalformedContainer(format!("credential has no claim at {pointer}")))?;
    disclosures[index] = Disclosure::Disclose;
  }
  Ok(disclosures)
}
