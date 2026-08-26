// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Blind BBS with key binding.
//!
//! Ported from Emil Lundberg's TypeScript implementation
//! (`emlun/wallet-common@blind-bbs-schnorr`, `src/bbs/blind_bbs.ts`), which
//! tracks draft-irtf-cfrg-bbs-blind-signatures with the key binding
//! extension of his CFRG PR #48 plus the four prototype-firmware deltas
//! recorded in `PROFILE.md` §3.
//!
//! The two-phase `*Init` / `*Finalize` split is load-bearing, not
//! stylistic: a device signature is produced between the halves, and on the
//! web that means a WebAuthn call on the main thread while the computation
//! lives in a worker. The intermediate state is therefore always a
//! serializable octet string.

use bls12_381_plus::ff::Field;
use bls12_381_plus::{G1Projective, Scalar};
use sha2::{Digest, Sha256};

use crate::bbs::{Ser, Signature, octets_to_point_e1, octets_to_pubkey, scalar_from_be, serialize};
use crate::error::{Error, Result};
use crate::keybind::SignatureScheme;
use crate::suite::{OCTET_POINT_LENGTH, OCTET_SCALAR_LENGTH, Suite};
use crate::util::{i2osp, sumprod};

/// What the holder wants done with one message at presentation time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disclosure {
  /// Reveal the message to the verifier.
  Disclose,
  /// Prove knowledge of it without revealing it.
  Hide,
  /// Hide it, but also emit a Pedersen commitment the verifier can carry
  /// into a further proof.
  Commit,
}

impl std::str::FromStr for Disclosure {
  type Err = Error;

  fn from_str(s: &str) -> Result<Self> {
    match s {
      "DISCLOSE" => Ok(Disclosure::Disclose),
      "HIDE" => Ok(Disclosure::Hide),
      "COMMIT" => Ok(Disclosure::Commit),
      _ => Err(Error::Unsupported("unknown disclosure choice")),
    }
  }
}

fn sum_points(points: &[G1Projective]) -> G1Projective {
  points.iter().fold(G1Projective::IDENTITY, |acc, p| acc + p)
}

fn read_u64(octets: &[u8], at: usize) -> Result<usize> {
  let slice: [u8; 8] = octets.get(at..at + 8).and_then(|s| s.try_into().ok()).ok_or(Error::InvalidLength {
    what: "length prefix",
    expected: at + 8,
    got: octets.len(),
  })?;
  Ok(u64::from_be_bytes(slice) as usize)
}

/// Blind suite id for the Schnorr key binding construction.
pub const SCHNORR_SUITE_ID: &str = "BBS-SCHNORR_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// Blind suite id for plain blind BBS with no key binding.
pub const PLAIN_SUITE_ID: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";

/// A blind BBS cipher suite: base BBS plus a key binding scheme.
///
/// Note that `bbs.api_id` here is the **blind** api_id
/// (`<blind suite id> || "BLIND_H2G_HM2S_"`), not the base BBS one — every
/// operation in the blind layer, including `messages_to_scalars` and
/// `calculate_domain`, is domain-separated under it. Mixing the two
/// produces values that verify against nothing.
pub struct BlindSuite<S: SignatureScheme> {
  pub bbs: Suite,
  pub sig: S,
}

/// Wallet-side state between `commit_init` and `commit_finalize`.
type CommitState = (G1Projective, Scalar, Vec<Scalar>, Scalar, Vec<G1Projective>);

impl<S: SignatureScheme> BlindSuite<S> {
  /// Build a blind suite. `suite_id` selects the blind api_id domain
  /// separation, e.g. [`SCHNORR_SUITE_ID`].
  pub fn new(mut bbs: Suite, sig: S, suite_id: &str) -> Self {
    bbs.api_id = format!("{suite_id}BLIND_H2G_HM2S_").into_bytes();
    Self { bbs, sig }
  }

  fn blind_generators(&self, count: usize) -> Result<Vec<G1Projective>> {
    let mut s = self.bbs.clone();
    s.api_id = [b"BLIND_".as_slice(), &self.bbs.api_id].concat();
    s.create_generators(count)
  }

  /// **DELTA 1** — the first key binding generator is the curve's own base
  /// point (`BP1`), because a hardware authenticator can only scalar
  /// multiply the standard generator, not a suite-derived one. Remaining
  /// generators come from a `KEYBIND_`-prefixed api_id.
  fn keybind_generators(&self, k: usize) -> Result<Vec<G1Projective>> {
    if k == 0 {
      return Ok(Vec::new());
    }
    let mut s = self.bbs.clone();
    s.api_id = [b"KEYBIND_".as_slice(), &self.bbs.api_id].concat();
    let mut out = vec![G1Projective::GENERATOR];
    out.extend(s.create_generators(k - 1)?);
    out.truncate(k);
    Ok(out)
  }

  fn com_dis_generators(&self) -> Result<(G1Projective, G1Projective)> {
    let mut s = self.bbs.clone();
    s.api_id = [b"COM_DIS_".as_slice(), &self.bbs.api_id].concat();
    let g = s.create_generators(2)?;
    Ok((g[0], g[1]))
  }

  fn parse_keybind_public_keys(&self, keys: &[Vec<u8>]) -> Result<Vec<G1Projective>> {
    keys
      .iter()
      .map(|octs| {
        let p = octets_to_point_e1(octs)?;
        if bool::from(p.is_identity()) {
          return Err(Error::InvalidPoint("key binding public key is the identity"));
        }
        Ok(p)
      })
      .collect()
  }

  // ---- Commitment (issuance, wallet side) ----------------------------

  /// `CommitInit` — returns the opaque state, the prover blind that must be
  /// stored with the credential, and the challenge for the device to sign.
  pub fn commit_init(&self, committed_messages: &[Vec<u8>], keybind_public_keys: &[Vec<u8>]) -> Result<(Vec<u8>, Scalar, Scalar)> {
    let k = keybind_public_keys.len();
    let pks = self.parse_keybind_public_keys(keybind_public_keys)?;
    let committed_scalars = self.bbs.messages_to_scalars(committed_messages)?;
    let blind_generators = self.blind_generators(committed_scalars.len() + 1)?;
    let keybind_generators = self.keybind_generators(k)?;
    let generators = [blind_generators, keybind_generators].concat();

    let (state, secret_prover_blind, challenge) = self.core_commit_init(&generators, &committed_scalars, &pks)?;
    Ok((commitment_state_to_octets(&state), secret_prover_blind, challenge))
  }

  fn core_commit_init(
    &self,
    blind_generators: &[G1Projective],
    committed_scalars: &[Scalar],
    keybind_public_keys: &[G1Projective],
  ) -> Result<(CommitState, Scalar, Scalar)> {
    let m = committed_scalars.len();
    let k = keybind_public_keys.len();
    if blind_generators.len() != m + k + 1 {
      return Err(Error::MismatchedLengths {
        what: "blind generators",
        a: blind_generators.len(),
        b: m + k + 1,
      });
    }
    let (q_2, rest) = blind_generators.split_first().expect("length checked above");
    let js = &rest[..m];

    let randoms = self.bbs.scalars.calculate(m + 2)?;
    let secret_prover_blind = randoms[0];
    let s_tilde = randoms[1];
    let m_tilde = &randoms[2..];

    let mut js_q2 = js.to_vec();
    js_q2.push(*q_2);
    let mut msg_blind = committed_scalars.to_vec();
    msg_blind.push(secret_prover_blind);
    let c = sumprod(&js_q2, &msg_blind)?;

    let mut mt_st = m_tilde.to_vec();
    mt_st.push(s_tilde);
    let cbar = sumprod(&js_q2, &mt_st)?;

    let challenge = self.calculate_blind_challenge(&c, &cbar, blind_generators, keybind_public_keys)?;
    let s_hat = s_tilde + secret_prover_blind * challenge;
    let m_hat: Vec<Scalar> = m_tilde.iter().zip(committed_scalars.iter()).map(|(mt, msg)| mt + msg * challenge).collect();

    Ok(((c, s_hat, m_hat, challenge, keybind_public_keys.to_vec()), secret_prover_blind, challenge))
  }

  /// `CommitFinalize` — folds the device's signatures over the commit
  /// challenge into the commitment the issuer will verify.
  pub fn commit_finalize(&self, state: &[u8], keybind_signatures: &[Vec<u8>]) -> Result<Vec<u8>> {
    let (c, s_hat, m_hat, challenge, keybind_public_keys) = octets_to_commitment_state(state)?;
    if keybind_signatures.len() != keybind_public_keys.len() {
      return Err(Error::MismatchedLengths {
        what: "key binding signatures",
        a: keybind_signatures.len(),
        b: keybind_public_keys.len(),
      });
    }
    Ok(commitment_with_proof_to_octets(
      &c,
      &keybind_public_keys,
      &s_hat,
      &m_hat,
      &challenge,
      keybind_signatures,
    ))
  }

  fn calculate_blind_challenge(
    &self,
    c: &G1Projective,
    cbar: &G1Projective,
    generators: &[G1Projective],
    keybind_public_keys: &[G1Projective],
  ) -> Result<Scalar> {
    if generators.is_empty() {
      return Err(Error::MismatchedLengths {
        what: "generators",
        a: 0,
        b: 1,
      });
    }
    let k = keybind_public_keys.len();
    let m = generators.len() - 1 - k;

    let mut items = vec![Ser::U64(m as u64), Ser::U64(k as u64)];
    items.extend(generators.iter().map(|g| Ser::G1(*g)));
    items.extend(keybind_public_keys.iter().map(|p| Ser::G1(*p)));
    items.push(Ser::G1(*c));
    items.push(Ser::G1(*cbar));

    self.bbs.hash_to_scalar(&serialize(&items), &self.bbs.dst(b"H2S_"))
  }

  // ---- Issuer side ----------------------------------------------------

  /// Verify a commitment and produce a blind BBS signature over it plus the
  /// issuer's own messages. This is the only operation an issuer needs.
  pub fn blind_sign(&self, sk: &Scalar, pk: &[u8], commitment_with_proof: &[u8], header: &[u8], messages: &[Vec<u8>]) -> Result<Vec<u8>> {
    let (commitment, keybind_public_keys, blind_generators) = self.deserialize_and_validate_commit(commitment_with_proof)?;

    let message_scalars = self.bbs.messages_to_scalars(messages)?;
    let generators = self.bbs.create_generators(messages.len() + 1)?;
    let commitment_plus_keys = commitment + sum_points(&keybind_public_keys);

    let b = self.b_calculate(pk, &generators, &blind_generators, &commitment_plus_keys, &message_scalars, header)?;
    self.finalize_blind_sign(sk, &b)
  }

  fn b_calculate(
    &self,
    pk: &[u8],
    generators: &[G1Projective],
    blind_generators: &[G1Projective],
    commitment: &G1Projective,
    message_scalars: &[Scalar],
    header: &[u8],
  ) -> Result<G1Projective> {
    let l = message_scalars.len();
    if generators.len() != l + 1 {
      return Err(Error::MismatchedLengths {
        what: "messages and generators",
        a: l,
        b: generators.len(),
      });
    }
    if blind_generators.is_empty() {
      return Err(Error::MismatchedLengths {
        what: "blind generators",
        a: 0,
        b: 1,
      });
    }
    let (q_1, h_points) = generators.split_first().expect("length checked above");
    let (q_2, j_points) = blind_generators.split_first().expect("length checked above");

    let mut domain_gens = h_points.to_vec();
    domain_gens.push(*q_2);
    domain_gens.extend_from_slice(j_points);
    let domain = self.bbs.calculate_domain(pk, q_1, &domain_gens, header)?;

    let mut points = vec![self.bbs.p1, *q_1];
    points.extend_from_slice(h_points);
    points.push(*commitment);
    let mut scalars = vec![Scalar::ONE, domain];
    scalars.extend_from_slice(message_scalars);
    scalars.push(Scalar::ONE);

    let b = sumprod(&points, &scalars)?;
    if bool::from(b.is_identity()) {
      return Err(Error::InvalidPoint("B must not be the identity"));
    }
    Ok(b)
  }

  fn finalize_blind_sign(&self, sk: &Scalar, b: &G1Projective) -> Result<Vec<u8>> {
    if bool::from(b.is_identity()) {
      return Err(Error::InvalidPoint("B must not be the identity"));
    }
    let e_octs = serialize(&[Ser::Scalar(*sk), Ser::G1(*b)]);
    let e = self.bbs.hash_to_scalar(&e_octs, &self.bbs.dst(b"H2S_"))?;
    let inv: Option<Scalar> = (sk + e).invert().into();
    let inv = inv.ok_or(Error::InvalidScalar("SK + e is not invertible"))?;
    Ok(Signature { a: b * inv, e }.to_octets())
  }

  #[allow(clippy::type_complexity)]
  fn deserialize_and_validate_commit(&self, commitment_with_proof: &[u8]) -> Result<(G1Projective, Vec<G1Projective>, Vec<G1Projective>)> {
    let (c, keybind_public_keys, s_hat, m_hat, challenge, keybind_signatures) =
      octets_to_commitment_with_proof(commitment_with_proof, self.sig.signature_length())?;

    let blind_generators = self.blind_generators(m_hat.len() + 1)?;
    let keybind_generators = self.keybind_generators(keybind_signatures.len())?;
    let generators = [blind_generators, keybind_generators].concat();

    self.core_commit_verify(&c, &keybind_public_keys, &s_hat, &m_hat, &challenge, &keybind_signatures, &generators)?;
    Ok((c, keybind_public_keys, generators))
  }

  #[allow(clippy::too_many_arguments)]
  fn core_commit_verify(
    &self,
    commitment: &G1Projective,
    keybind_public_keys: &[G1Projective],
    s_hat: &Scalar,
    m_hat: &[Scalar],
    cp: &Scalar,
    keybind_signatures: &[Vec<u8>],
    blind_generators: &[G1Projective],
  ) -> Result<()> {
    let m = m_hat.len();
    let k = keybind_public_keys.len();
    if blind_generators.len() != m + k + 1 {
      return Err(Error::MismatchedLengths {
        what: "blind generators",
        a: blind_generators.len(),
        b: m + k + 1,
      });
    }
    if keybind_signatures.len() != k {
      return Err(Error::MismatchedLengths {
        what: "key binding signatures",
        a: keybind_signatures.len(),
        b: k,
      });
    }
    let (q_2, rest) = blind_generators.split_first().expect("length checked above");
    let js = &rest[..m];
    let kjs = &rest[m..];

    let mut points = js.to_vec();
    points.push(*q_2);
    points.push(*commitment);
    let mut scalars = m_hat.to_vec();
    scalars.push(*s_hat);
    scalars.push(-cp);
    let cbar = sumprod(&points, &scalars)?;

    let cv = self.calculate_blind_challenge(commitment, &cbar, blind_generators, keybind_public_keys)?;
    if cv != *cp {
      return Err(Error::VerificationFailed("commitment challenge"));
    }
    // The device proved possession of each key binding key by signing the
    // commit challenge.
    let challenge_octets = serialize(&[Ser::Scalar(*cp)]);
    for (i, sig) in keybind_signatures.iter().enumerate() {
      self.sig.verify(&kjs[i], &keybind_public_keys[i], sig, &challenge_octets)?;
    }
    Ok(())
  }

  /// `VerifyBlindSign` — the holder's check that the issuer signed what it
  /// was supposed to. Must be run before storing a credential.
  #[allow(clippy::too_many_arguments)]
  pub fn verify_blind_sign(
    &self,
    pk: &[u8],
    signature: &[u8],
    header: &[u8],
    messages: &[Vec<u8>],
    issuer_known_messages_no: usize,
    keybind_public_keys: &[Vec<u8>],
    secret_prover_blind: &Scalar,
  ) -> Result<()> {
    let l = messages.len();
    if issuer_known_messages_no > l {
      return Err(Error::TooMany("issuer-known messages"));
    }
    let k = keybind_public_keys.len();
    let pks = self.parse_keybind_public_keys(keybind_public_keys)?;

    let generators = self.bbs.create_generators(issuer_known_messages_no + 1)?;
    let blind_generators = self.blind_generators(l - issuer_known_messages_no + 1)?;
    let keybind_generators = self.keybind_generators(k)?;

    let message_scalars = self.bbs.messages_to_scalars(messages)?;
    let mut proof_scalars = message_scalars[..issuer_known_messages_no].to_vec();
    proof_scalars.push(*secret_prover_blind);
    proof_scalars.extend_from_slice(&message_scalars[issuer_known_messages_no..]);

    let all_generators = [generators, blind_generators, keybind_generators].concat();
    self.blind_core_verify(pk, signature, &all_generators, header, &proof_scalars, &pks)
  }

  fn blind_core_verify(
    &self,
    pk: &[u8],
    signature: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    messages: &[Scalar],
    keybind_public_keys: &[G1Projective],
  ) -> Result<()> {
    use bls12_381_plus::{G1Affine, G2Affine, G2Prepared, G2Projective, Gt, multi_miller_loop};

    let sig = Signature::from_octets(signature)?;
    let w = octets_to_pubkey(pk)?;
    let l = messages.len();
    let k = keybind_public_keys.len();
    if generators.len() != l + k + 1 {
      return Err(Error::MismatchedLengths {
        what: "messages, keys and generators",
        a: generators.len(),
        b: l + k + 1,
      });
    }
    let (q_1, rest) = generators.split_first().expect("length checked above");
    let hs = &rest[..l];

    let domain = self.bbs.calculate_domain(pk, q_1, rest, header)?;
    let b = self.bbs.p1 + q_1 * domain + sumprod(hs, messages)? + sum_points(keybind_public_keys);

    // e(A, W) * e(A*e - B, G2) == 1
    let lhs = G2Prepared::from(G2Affine::from(w));
    let rhs = G2Prepared::from(G2Affine::from(G2Projective::GENERATOR));
    let result = multi_miller_loop(&[(&G1Affine::from(sig.a), &lhs), (&G1Affine::from(sig.a * sig.e - b), &rhs)]).final_exponentiation();
    if result != Gt::IDENTITY {
      return Err(Error::VerificationFailed("blind signature pairing check"));
    }
    Ok(())
  }
}

// ---- Commitment serialization -------------------------------------------

fn commitment_state_to_octets(state: &CommitState) -> Vec<u8> {
  let (c, s_hat, m_hat, challenge, keybind_public_keys) = state;
  let mut items = vec![
    Ser::U64(m_hat.len() as u64),
    Ser::U64(keybind_public_keys.len() as u64),
    Ser::G1(*c),
    Ser::Scalar(*s_hat),
  ];
  items.extend(m_hat.iter().map(|s| Ser::Scalar(*s)));
  items.push(Ser::Scalar(*challenge));
  items.extend(keybind_public_keys.iter().map(|p| Ser::G1(*p)));
  serialize(&items)
}

fn octets_to_commitment_state(octets: &[u8]) -> Result<CommitState> {
  if octets.len() < 16 {
    return Err(Error::InvalidLength {
      what: "commitment state",
      expected: 16,
      got: octets.len(),
    });
  }
  let m = read_u64(octets, 0)?;
  let k = read_u64(octets, 8)?;
  let expected = 16 + (1 + k) * OCTET_POINT_LENGTH + (2 + m) * OCTET_SCALAR_LENGTH;
  if octets.len() != expected {
    return Err(Error::InvalidLength {
      what: "commitment state",
      expected,
      got: octets.len(),
    });
  }

  let mut idx = 16;
  let c = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
  if bool::from(c.is_identity()) {
    return Err(Error::InvalidPoint("commitment is the identity"));
  }
  idx += OCTET_POINT_LENGTH;

  let mut scalars = Vec::with_capacity(m + 2);
  for _ in 0..=(m + 1) {
    let s = scalar_from_be(&octets[idx..idx + OCTET_SCALAR_LENGTH])?;
    if bool::from(s.is_zero()) {
      return Err(Error::InvalidScalar("commitment state scalar is zero"));
    }
    scalars.push(s);
    idx += OCTET_SCALAR_LENGTH;
  }

  let mut pks = Vec::with_capacity(k);
  for _ in 0..k {
    let p = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
    if bool::from(p.is_identity()) {
      return Err(Error::InvalidPoint("key binding public key is the identity"));
    }
    pks.push(p);
    idx += OCTET_POINT_LENGTH;
  }

  Ok((c, scalars[0], scalars[1..1 + m].to_vec(), scalars[m + 1], pks))
}

fn commitment_with_proof_to_octets(
  c: &G1Projective,
  keybind_public_keys: &[G1Projective],
  s_hat: &Scalar,
  m_hat: &[Scalar],
  challenge: &Scalar,
  keybind_signatures: &[Vec<u8>],
) -> Vec<u8> {
  let mut items = vec![Ser::U64(m_hat.len() as u64), Ser::U64(keybind_public_keys.len() as u64), Ser::G1(*c)];
  items.extend(keybind_public_keys.iter().map(|p| Ser::G1(*p)));
  items.push(Ser::Scalar(*s_hat));
  items.extend(m_hat.iter().map(|s| Ser::Scalar(*s)));
  items.push(Ser::Scalar(*challenge));

  let mut out = serialize(&items);
  for sig in keybind_signatures {
    out.extend_from_slice(sig);
  }
  out
}

#[allow(clippy::type_complexity)]
fn octets_to_commitment_with_proof(
  octets: &[u8],
  signature_length: usize,
) -> Result<(G1Projective, Vec<G1Projective>, Scalar, Vec<Scalar>, Scalar, Vec<Vec<u8>>)> {
  if octets.len() < 16 {
    return Err(Error::InvalidLength {
      what: "commitment",
      expected: 16,
      got: octets.len(),
    });
  }
  let m = read_u64(octets, 0)?;
  let k = read_u64(octets, 8)?;
  let expected = 16 + (1 + k) * OCTET_POINT_LENGTH + (2 + m) * OCTET_SCALAR_LENGTH + k * signature_length;
  if octets.len() != expected {
    return Err(Error::InvalidLength {
      what: "commitment",
      expected,
      got: octets.len(),
    });
  }

  let mut idx = 16;
  let c = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
  if bool::from(c.is_identity()) {
    return Err(Error::InvalidPoint("commitment is the identity"));
  }
  idx += OCTET_POINT_LENGTH;

  let mut pks = Vec::with_capacity(k);
  for _ in 0..k {
    let p = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
    if bool::from(p.is_identity()) {
      return Err(Error::InvalidPoint("key binding public key is the identity"));
    }
    pks.push(p);
    idx += OCTET_POINT_LENGTH;
  }

  let mut scalars = Vec::with_capacity(m + 2);
  for _ in 0..=(m + 1) {
    let s = scalar_from_be(&octets[idx..idx + OCTET_SCALAR_LENGTH])?;
    if bool::from(s.is_zero()) {
      return Err(Error::InvalidScalar("commitment scalar is zero"));
    }
    scalars.push(s);
    idx += OCTET_SCALAR_LENGTH;
  }

  let mut sigs = Vec::with_capacity(k);
  for _ in 0..k {
    sigs.push(octets[idx..idx + signature_length].to_vec());
    idx += signature_length;
  }

  Ok((c, pks, scalars[0], scalars[1..1 + m].to_vec(), scalars[m + 1], sigs))
}

/// SHA-256, used for the key binding challenge prehash (DELTA 3).
pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
  Sha256::digest(data).to_vec()
}

/// Serialize a BBS proof plus blind extras. Exposed for the proof module.
pub(crate) fn proof_prefix(bbs_proof_len: usize, n: usize, k: usize) -> Vec<u8> {
  [i2osp(bbs_proof_len as u64, 8), i2osp(n as u64, 8), i2osp(k as u64, 8)].concat()
}

// ---- Presentation --------------------------------------------------------

/// What `blind_proof_gen_init` hands back alongside the state: the committed
/// message values and their blinding factors, for a verifier-side follow-on
/// proof over the Pedersen commitments.
pub type AddZkpInfo = (Vec<Scalar>, Vec<Scalar>);

impl<S: SignatureScheme> BlindSuite<S> {
  /// `BlindProofGenInit` — everything up to the point where the device must
  /// sign. Returns the opaque state, the extra ZKP info, and one challenge
  /// per key binding key for the authenticator to sign.
  ///
  /// **DELTA 3**: each returned challenge is already SHA-256'd. The
  /// authenticator signs a bare 32-octet digest because the prototype
  /// firmware caps signed messages at 64 octets and the underlying
  /// challenge is 80.
  #[allow(clippy::too_many_arguments)]
  pub fn blind_proof_gen_init(
    &self,
    pk: &[u8],
    signature: &[u8],
    header: &[u8],
    ph: &[u8],
    messages: &[Vec<u8>],
    issuer_known_messages_no: usize,
    message_disclosures: &[Disclosure],
    keybind_public_keys: &[Vec<u8>],
    secret_prover_blind: &Scalar,
  ) -> Result<(Vec<u8>, AddZkpInfo, Vec<Vec<u8>>)> {
    let l = messages.len();
    if message_disclosures.len() != l {
      return Err(Error::MismatchedLengths {
        what: "message disclosures",
        a: message_disclosures.len(),
        b: l,
      });
    }
    if issuer_known_messages_no > l {
      return Err(Error::TooMany("issuer-known messages"));
    }
    let disclosed_indexes: Vec<usize> = (0..l).filter(|&i| message_disclosures[i] == Disclosure::Disclose).collect();
    let commitment_indexes: Vec<usize> = (0..l).filter(|&i| message_disclosures[i] == Disclosure::Commit).collect();
    let k = keybind_public_keys.len();
    let pks = self.parse_keybind_public_keys(keybind_public_keys)?;

    let generators = self.bbs.create_generators(issuer_known_messages_no + 1)?;
    let blind_generators = self.blind_generators(l - issuer_known_messages_no + 1)?;
    let keybind_generators = self.keybind_generators(k)?;
    let all_generators = [generators, blind_generators, keybind_generators].concat();

    let message_scalars = self.bbs.messages_to_scalars(messages)?;
    let mut proof_scalars = message_scalars[..issuer_known_messages_no].to_vec();
    proof_scalars.push(*secret_prover_blind);
    proof_scalars.extend_from_slice(&message_scalars[issuer_known_messages_no..]);

    // The prover blind occupies one slot, so every message at or after
    // `issuer_known_messages_no` shifts up by one.
    let proof_index = |i: usize| if i < issuer_known_messages_no { i } else { i + 1 };
    let proof_disclosed: Vec<usize> = disclosed_indexes.iter().map(|&i| proof_index(i)).collect();
    let proof_commitments: Vec<usize> = commitment_indexes.iter().map(|&i| proof_index(i)).collect();

    self.core_proof_gen_init(
      pk,
      signature,
      &all_generators,
      header,
      ph,
      &proof_scalars,
      &proof_disclosed,
      &proof_commitments,
      &pks,
    )
  }

  #[allow(clippy::too_many_arguments)]
  fn core_proof_gen_init(
    &self,
    pk: &[u8],
    signature: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    messages: &[Scalar],
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
    keybind_public_keys: &[G1Projective],
  ) -> Result<(Vec<u8>, AddZkpInfo, Vec<Vec<u8>>)> {
    let (y_0, y_1) = self.com_dis_generators()?;
    let sig = Signature::from_octets(signature)?;
    let l = messages.len();
    check_indexes(commitment_indexes, l, "commitment_indexes")?;
    check_indexes(disclosed_indexes, l, "disclosed_indexes")?;
    if commitment_indexes.iter().any(|i| disclosed_indexes.contains(i)) {
      return Err(Error::Unsupported("disclosed and committed message indexes must be disjoint"));
    }

    let n = commitment_indexes.len();
    let r = disclosed_indexes.len();
    let u = l - r;
    let k = keybind_public_keys.len();
    let disclosed_messages: Vec<Scalar> = disclosed_indexes.iter().map(|&i| messages[i]).collect();
    let ji: Vec<usize> = (0..l).filter(|i| !disclosed_indexes.contains(i)).collect();
    let undisclosed_messages: Vec<Scalar> = ji.iter().map(|&i| messages[i]).collect();

    let init_random = self.bbs.scalars.calculate(5 + u + 2 * k)?;
    let (r1, r2, e_tilde, r1_tilde, r3_tilde) = (init_random[0], init_random[1], init_random[2], init_random[3], init_random[4]);
    let rest = &init_random[5..];
    let m_tilde = &rest[..u];
    let m_tilde_and_r_key_tilde = &rest[..u + k];
    let r_key = &rest[u + k..];

    // The key binding keys ride along as K extra "messages" fixed to zero,
    // undisclosed, so the BBS proof covers them.
    let mut proof_init_scalars = vec![r1, r2, e_tilde, r1_tilde, r3_tilde];
    proof_init_scalars.extend_from_slice(m_tilde_and_r_key_tilde);
    let mut padded_messages = messages.to_vec();
    padded_messages.extend(std::iter::repeat_n(Scalar::ZERO, k));
    let mut padded_undisclosed = ji.clone();
    padded_undisclosed.extend((0..k).map(|i| l + i));

    let init = self
      .bbs
      .proof_init(pk, &sig, generators, &proof_init_scalars, header, &padded_messages, &padded_undisclosed)?;

    let d_add = sum_points(keybind_public_keys) * r2;
    let abar = init.abar;
    let d = init.d + d_add;
    let bbar = init.bbar + d_add * r1;
    let t1 = init.t1 + d_add * r1_tilde;
    let t2 = init.t2 + d_add * r3_tilde;
    let pk_tildes: Vec<G1Projective> = (0..k).map(|i| keybind_public_keys[i] + generators[l + 1 + i] * r_key[i]).collect();

    let s_and_s_tilde = self.bbs.scalars.calculate(2 * n)?;
    let s = &s_and_s_tilde[..n];
    let s_tilde = &s_and_s_tilde[n..];
    let mut commitments = Vec::with_capacity(n);
    let mut commitment_proofs = Vec::with_capacity(n);
    for i in 0..n {
      let idx = commitment_indexes[i];
      commitments.push(y_0 * s[i] + y_1 * messages[idx]);
      let k_idx = ji
        .iter()
        .position(|&j| j == idx)
        .ok_or(Error::Unsupported("committed message must be undisclosed"))?;
      commitment_proofs.push(y_0 * s_tilde[i] + y_1 * m_tilde[k_idx]);
    }

    let modified = crate::bbs::ProofInitResult {
      abar,
      bbar,
      d,
      t1,
      t2,
      domain: init.domain,
    };
    let challenge = self.blind_proof_challenge_calculate(
      &modified,
      &commitments,
      &commitment_proofs,
      commitment_indexes,
      &pk_tildes,
      &disclosed_messages,
      disclosed_indexes,
      ph,
    )?;

    let mut finalize_undisclosed = undisclosed_messages.clone();
    finalize_undisclosed.extend(r_key.iter().map(|rk| -rk));
    let bbs_proof = self
      .bbs
      .proof_finalize(&modified, &challenge, &sig.e, &proof_init_scalars, &finalize_undisclosed)?
      .to_octets();

    let s_hat: Vec<Scalar> = s_tilde.iter().zip(s.iter()).map(|(st, si)| st + challenge * si).collect();

    let state = proof_gen_state_to_octets(&bbs_proof, &challenge, &commitments, &s_hat, &pk_tildes, r_key);

    // DELTA 3: prehash, because the authenticator caps messages at 64 octets.
    let keybind_challenges: Vec<Vec<u8>> = pk_tildes.iter().map(|pt| sha256(&serialize(&[Ser::G1(*pt), Ser::Scalar(challenge)]))).collect();

    let add_zkp_info = (commitment_indexes.iter().map(|&i| messages[i]).collect(), s.to_vec());
    Ok((state, add_zkp_info, keybind_challenges))
  }

  /// `BlindProofGenFinalize` — folds the device's signatures into the proof.
  pub fn blind_proof_gen_finalize(&self, state: &[u8], keybind_signatures: &[Vec<u8>]) -> Result<Vec<u8>> {
    let (incomplete_proof, challenge, pk_tildes, r_key) = octets_to_proof_gen_state(state)?;
    let k = pk_tildes.len();
    if keybind_signatures.len() != k {
      return Err(Error::MismatchedLengths {
        what: "key binding signatures",
        a: keybind_signatures.len(),
        b: k,
      });
    }
    let mut proof = incomplete_proof;
    let pk_tilde_octs: Vec<Vec<u8>> = pk_tildes.iter().map(|p| serialize(&[Ser::G1(*p)])).collect();
    for octs in &pk_tilde_octs {
      proof.extend_from_slice(octs);
    }
    let challenge_octs = serialize(&[Ser::Scalar(challenge)]);
    for i in 0..k {
      let message = sha256(&[pk_tilde_octs[i].clone(), challenge_octs.clone()].concat());
      proof.extend_from_slice(&self.sig.adapt_sig(&keybind_signatures[i], &r_key[i], &message)?);
    }
    Ok(proof)
  }

  #[allow(clippy::too_many_arguments)]
  fn blind_proof_challenge_calculate(
    &self,
    init: &crate::bbs::ProofInitResult,
    commitments: &[G1Projective],
    commitment_proofs: &[G1Projective],
    commitment_indexes: &[usize],
    keybind_randomized_keys: &[G1Projective],
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
    ph: &[u8],
  ) -> Result<Scalar> {
    let r = disclosed_indexes.len();
    if disclosed_messages.len() != r {
      return Err(Error::MismatchedLengths {
        what: "disclosed messages and indexes",
        a: disclosed_messages.len(),
        b: r,
      });
    }
    let n = commitments.len();
    if commitment_proofs.len() != n || commitment_indexes.len() != n {
      return Err(Error::MismatchedLengths {
        what: "commitments",
        a: commitment_proofs.len(),
        b: n,
      });
    }

    let mut c_arr = vec![Ser::U64(r as u64)];
    for (i, m) in disclosed_indexes.iter().zip(disclosed_messages.iter()) {
      c_arr.push(Ser::U64(*i as u64));
      c_arr.push(Ser::Scalar(*m));
    }
    c_arr.extend([
      Ser::G1(init.abar),
      Ser::G1(init.bbar),
      Ser::G1(init.d),
      Ser::G1(init.t1),
      Ser::G1(init.t2),
      Ser::Scalar(init.domain),
    ]);

    let mut commitment_arr = vec![Ser::U64(n as u64)];
    for i in 0..n {
      commitment_arr.push(Ser::U64(commitment_indexes[i] as u64));
      commitment_arr.push(Ser::G1(commitments[i]));
      commitment_arr.push(Ser::G1(commitment_proofs[i]));
    }

    let mut keybind_arr = vec![Ser::U64(keybind_randomized_keys.len() as u64)];
    keybind_arr.extend(keybind_randomized_keys.iter().map(|p| Ser::G1(*p)));

    let mut c_octs = serialize(&c_arr);
    c_octs.extend_from_slice(&serialize(&commitment_arr));
    c_octs.extend_from_slice(&serialize(&keybind_arr));
    c_octs.extend_from_slice(&i2osp(ph.len() as u64, 8));
    c_octs.extend_from_slice(ph);
    self.bbs.hash_to_scalar(&c_octs, &self.bbs.dst(b"H2S_"))
  }
}

fn check_indexes(indexes: &[usize], len: usize, _what: &str) -> Result<()> {
  for w in indexes.windows(2) {
    if w[0] >= w[1] {
      return Err(Error::Unsupported("indexes must be strictly increasing"));
    }
  }
  for &i in indexes {
    if i >= len {
      return Err(Error::IndexOutOfRange { index: i, len });
    }
  }
  Ok(())
}

fn proof_gen_state_to_octets(
  bbs_proof: &[u8],
  challenge: &Scalar,
  commitments: &[G1Projective],
  commitment_proofs: &[Scalar],
  keybind_randomized_keys: &[G1Projective],
  keybind_randomizers: &[Scalar],
) -> Vec<u8> {
  let n = commitments.len();
  let k = keybind_randomized_keys.len();
  let mut out = proof_prefix(bbs_proof.len(), n, k);
  out.extend_from_slice(bbs_proof);

  let mut items: Vec<Ser> = commitments.iter().map(|c| Ser::G1(*c)).collect();
  items.extend(commitment_proofs.iter().map(|s| Ser::Scalar(*s)));
  items.push(Ser::Scalar(*challenge));
  items.extend(keybind_randomized_keys.iter().map(|p| Ser::G1(*p)));
  items.extend(keybind_randomizers.iter().map(|s| Ser::Scalar(*s)));
  out.extend_from_slice(&serialize(&items));
  out
}

#[allow(clippy::type_complexity)]
fn octets_to_proof_gen_state(octets: &[u8]) -> Result<(Vec<u8>, Scalar, Vec<G1Projective>, Vec<Scalar>)> {
  if octets.len() < 24 {
    return Err(Error::InvalidLength {
      what: "proof generation state",
      expected: 24,
      got: octets.len(),
    });
  }
  let bbs_proof_len = read_u64(octets, 0)?;
  let n = read_u64(octets, 8)?;
  let k = read_u64(octets, 16)?;
  let expected = 24 + bbs_proof_len + (n + k) * OCTET_POINT_LENGTH + (1 + n + k) * OCTET_SCALAR_LENGTH;
  if octets.len() != expected {
    return Err(Error::InvalidLength {
      what: "proof generation state",
      expected,
      got: octets.len(),
    });
  }

  let mut idx = octets.len() - k * (OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH);
  let incomplete_proof = octets[..idx - OCTET_SCALAR_LENGTH].to_vec();
  let challenge = scalar_from_be(&octets[idx - OCTET_SCALAR_LENGTH..idx])?;
  if bool::from(challenge.is_zero()) {
    return Err(Error::InvalidScalar("challenge is zero"));
  }

  let mut pk_tildes = Vec::with_capacity(k);
  for _ in 0..k {
    let p = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
    if bool::from(p.is_identity()) {
      return Err(Error::InvalidPoint("randomized key is the identity"));
    }
    pk_tildes.push(p);
    idx += OCTET_POINT_LENGTH;
  }
  let mut r_key = Vec::with_capacity(k);
  for _ in 0..k {
    let s = scalar_from_be(&octets[idx..idx + OCTET_SCALAR_LENGTH])?;
    if bool::from(s.is_zero()) {
      return Err(Error::InvalidScalar("key randomizer is zero"));
    }
    r_key.push(s);
    idx += OCTET_SCALAR_LENGTH;
  }
  Ok((incomplete_proof, challenge, pk_tildes, r_key))
}

// ---- Verification --------------------------------------------------------

impl<S: SignatureScheme> BlindSuite<S> {
  /// `BlindProofVerify` — the relying party's side. Everything needed is on
  /// the wire or in the request; there is no holder state here.
  #[allow(clippy::too_many_arguments)]
  pub fn blind_proof_verify(
    &self,
    pk: &[u8],
    proof: &[u8],
    header: &[u8],
    ph: &[u8],
    issuer_known_messages_no: usize,
    disclosed_messages: &[Vec<u8>],
    message_disclosures: &[Disclosure],
  ) -> Result<()> {
    if proof.len() < 24 {
      return Err(Error::InvalidLength {
        what: "proof",
        expected: 24,
        got: proof.len(),
      });
    }
    let bbs_proof_len = read_u64(proof, 0)?;
    let n = read_u64(proof, 8)?;
    let k = read_u64(proof, 16)?;

    let floor = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH;
    if bbs_proof_len < floor || !(bbs_proof_len - floor).is_multiple_of(OCTET_SCALAR_LENGTH) {
      return Err(Error::InvalidLength {
        what: "embedded BBS proof",
        expected: floor,
        got: bbs_proof_len,
      });
    }
    let undisclosed_msgs_no = (bbs_proof_len - floor) / OCTET_SCALAR_LENGTH;
    let proof_msgs_no = undisclosed_msgs_no + disclosed_messages.len();
    if proof_msgs_no == 0 {
      return Err(Error::TooMany("too few messages in proof"));
    }
    // One slot is the prover blind, K slots are key binding keys.
    let total_msgs_no = proof_msgs_no.checked_sub(1 + k).ok_or(Error::InvalidLength {
      what: "proof message count",
      expected: 1 + k,
      got: proof_msgs_no,
    })?;
    if issuer_known_messages_no > total_msgs_no {
      return Err(Error::TooMany("issuer-known messages"));
    }
    if message_disclosures.len() != total_msgs_no {
      return Err(Error::MismatchedLengths {
        what: "message disclosures",
        a: message_disclosures.len(),
        b: total_msgs_no,
      });
    }

    let disclosed_indexes: Vec<usize> = (0..total_msgs_no).filter(|&i| message_disclosures[i] == Disclosure::Disclose).collect();
    let commitment_indexes: Vec<usize> = (0..total_msgs_no).filter(|&i| message_disclosures[i] == Disclosure::Commit).collect();
    if disclosed_indexes.len() != disclosed_messages.len() {
      return Err(Error::MismatchedLengths {
        what: "disclosed messages",
        a: disclosed_indexes.len(),
        b: disclosed_messages.len(),
      });
    }
    if commitment_indexes.len() != n {
      return Err(Error::MismatchedLengths {
        what: "commitments",
        a: commitment_indexes.len(),
        b: n,
      });
    }

    let proof_index = |i: usize| if i < issuer_known_messages_no { i } else { i + 1 };
    let proof_disclosed: Vec<usize> = disclosed_indexes.iter().map(|&i| proof_index(i)).collect();
    let proof_commitments: Vec<usize> = commitment_indexes.iter().map(|&i| proof_index(i)).collect();

    let generators = self.bbs.create_generators(issuer_known_messages_no + 1)?;
    let blind_generators = self.blind_generators(total_msgs_no - issuer_known_messages_no + 1)?;
    let keybind_generators = self.keybind_generators(k)?;
    let all_generators = [generators, blind_generators, keybind_generators].concat();

    let message_scalars = self.bbs.messages_to_scalars(disclosed_messages)?;
    self.blind_core_proof_verify(pk, proof, &all_generators, header, ph, &message_scalars, &proof_disclosed, &proof_commitments)
  }

  #[allow(clippy::too_many_arguments)]
  fn blind_core_proof_verify(
    &self,
    pk: &[u8],
    proof: &[u8],
    generators: &[G1Projective],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
  ) -> Result<()> {
    use bls12_381_plus::{G1Affine, G2Affine, G2Prepared, G2Projective, Gt, multi_miller_loop};

    let (y_0, y_1) = self.com_dis_generators()?;
    let w = octets_to_pubkey(pk)?;
    let (bbs_proof, commitments, s_hat, pk_tildes, keybind_signatures) = octets_to_blind_proof(proof, self.sig.signature_length())?;

    let n = commitments.len();
    let k = pk_tildes.len();
    if s_hat.len() != n || commitment_indexes.len() != n {
      return Err(Error::MismatchedLengths {
        what: "commitments",
        a: s_hat.len(),
        b: n,
      });
    }
    let u = bbs_proof.commitments.len();
    let r = disclosed_indexes.len();
    if disclosed_messages.len() != r {
      return Err(Error::MismatchedLengths {
        what: "disclosed messages",
        a: disclosed_messages.len(),
        b: r,
      });
    }
    let l = r + u;
    if generators.len() != l + 1 {
      return Err(Error::MismatchedLengths {
        what: "generators",
        a: generators.len(),
        b: l + 1,
      });
    }
    if keybind_signatures.len() != k {
      return Err(Error::MismatchedLengths {
        what: "key binding signatures",
        a: keybind_signatures.len(),
        b: k,
      });
    }
    check_indexes(commitment_indexes, l, "commitment_indexes")?;
    check_indexes(disclosed_indexes, l, "disclosed_indexes")?;
    if commitment_indexes.iter().any(|i| disclosed_indexes.contains(i)) {
      return Err(Error::Unsupported("disclosed and committed message indexes must be disjoint"));
    }
    let ji: Vec<usize> = (0..l).filter(|i| !disclosed_indexes.contains(i)).collect();
    let cp = bbs_proof.challenge;

    let init = self
      .bbs
      .proof_verify_init(pk, &bbs_proof, generators, header, disclosed_messages, disclosed_indexes)?;
    let t2 = init.t2 + sum_points(&pk_tildes) * cp;

    let mut commitment_proofs = Vec::with_capacity(n);
    for i in 0..n {
      let idx = commitment_indexes[i];
      let k_idx = ji
        .iter()
        .position(|&j| j == idx)
        .ok_or(Error::Unsupported("committed message must be undisclosed"))?;
      commitment_proofs.push(y_0 * s_hat[i] + y_1 * bbs_proof.commitments[k_idx] - commitments[i] * cp);
    }

    let modified = crate::bbs::ProofInitResult {
      abar: init.abar,
      bbar: init.bbar,
      d: init.d,
      t1: init.t1,
      t2,
      domain: init.domain,
    };
    let challenge = self.blind_proof_challenge_calculate(
      &modified,
      &commitments,
      &commitment_proofs,
      commitment_indexes,
      &pk_tildes,
      disclosed_messages,
      disclosed_indexes,
      ph,
    )?;
    if challenge != cp {
      return Err(Error::VerificationFailed("proof challenge"));
    }

    // Each key binding signature must verify under the *randomized* key.
    for i in 0..k {
      let message = sha256(&serialize(&[Ser::G1(pk_tildes[i]), Ser::Scalar(challenge)]));
      self.sig.verify(&generators[l + 1 - k + i], &pk_tildes[i], &keybind_signatures[i], &message)?;
    }

    let lhs = G2Prepared::from(G2Affine::from(w));
    let rhs = G2Prepared::from(G2Affine::from(-G2Projective::GENERATOR));
    let result = multi_miller_loop(&[(&G1Affine::from(bbs_proof.abar), &lhs), (&G1Affine::from(bbs_proof.bbar), &rhs)]).final_exponentiation();
    if result != Gt::IDENTITY {
      return Err(Error::VerificationFailed("proof pairing check"));
    }
    Ok(())
  }
}

#[allow(clippy::type_complexity)]
fn octets_to_blind_proof(
  octets: &[u8],
  signature_length: usize,
) -> Result<(crate::bbs::Proof, Vec<G1Projective>, Vec<Scalar>, Vec<G1Projective>, Vec<Vec<u8>>)> {
  if octets.len() < 24 {
    return Err(Error::InvalidLength {
      what: "proof",
      expected: 24,
      got: octets.len(),
    });
  }
  let bbs_proof_len = read_u64(octets, 0)?;
  let n = read_u64(octets, 8)?;
  let k = read_u64(octets, 16)?;
  let expected = 24 + bbs_proof_len + n * (OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH) + k * (OCTET_POINT_LENGTH + signature_length);
  if octets.len() != expected {
    return Err(Error::InvalidLength {
      what: "proof",
      expected,
      got: octets.len(),
    });
  }

  let mut idx = 24;
  let bbs_proof = crate::bbs::Proof::from_octets(&octets[idx..idx + bbs_proof_len])?;
  idx += bbs_proof_len;

  let mut commitments = Vec::with_capacity(n);
  for _ in 0..n {
    let c = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
    if bool::from(c.is_identity()) {
      return Err(Error::InvalidPoint("commitment is the identity"));
    }
    commitments.push(c);
    idx += OCTET_POINT_LENGTH;
  }
  let mut s_hat = Vec::with_capacity(n);
  for _ in 0..n {
    s_hat.push(scalar_from_be(&octets[idx..idx + OCTET_SCALAR_LENGTH])?);
    idx += OCTET_SCALAR_LENGTH;
  }
  let mut pk_tildes = Vec::with_capacity(k);
  for _ in 0..k {
    let p = octets_to_point_e1(&octets[idx..idx + OCTET_POINT_LENGTH])?;
    if bool::from(p.is_identity()) {
      return Err(Error::InvalidPoint("randomized key is the identity"));
    }
    pk_tildes.push(p);
    idx += OCTET_POINT_LENGTH;
  }
  let mut sigs = Vec::with_capacity(k);
  for _ in 0..k {
    sigs.push(octets[idx..idx + signature_length].to_vec());
    idx += signature_length;
  }
  Ok((bbs_proof, commitments, s_hat, pk_tildes, sigs))
}
