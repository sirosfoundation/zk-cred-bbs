// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Base BBS, ported from draft-irtf-cfrg-bbs-signatures-08.
//!
//! Function names and parameter order deliberately mirror the draft (and
//! Emil Lundberg's TypeScript implementation in `wallet-common`, which is
//! this port's differential oracle) so the two can be read side by side.

use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use bls12_381_plus::{ff::Field, multi_miller_loop};

use crate::error::{Error, Result};
use crate::suite::{OCTET_POINT_LENGTH, OCTET_SCALAR_LENGTH, Suite};
use crate::util::{i2osp, sumprod};

/// One element of a `serialize()` input array (draft-08 §4.2.6).
#[derive(Clone, Debug)]
pub enum Ser {
  /// Serialized as `I2OSP(x, 8)`.
  U64(u64),
  /// Serialized as `I2OSP(x, octet_scalar_length)`.
  Scalar(Scalar),
  /// Serialized as `point_to_octets_E1` (48-byte compressed).
  G1(G1Projective),
  /// Serialized as `point_to_octets_E2` (96-byte compressed).
  G2(G2Projective),
  /// Passed through verbatim.
  Bytes(Vec<u8>),
}

/// `serialize(input_array)` (draft-08 §4.2.6).
pub fn serialize(items: &[Ser]) -> Vec<u8> {
  let mut out = Vec::new();
  for item in items {
    match item {
      Ser::U64(n) => out.extend_from_slice(&i2osp(*n, 8)),
      Ser::Scalar(s) => out.extend_from_slice(&s.to_be_bytes()),
      Ser::G1(p) => out.extend_from_slice(&G1Affine::from(p).to_compressed()),
      Ser::G2(p) => out.extend_from_slice(&G2Affine::from(p).to_compressed()),
      Ser::Bytes(b) => out.extend_from_slice(b),
    }
  }
  out
}

/// `octets_to_point_E1`, with the subgroup check the draft requires.
pub fn octets_to_point_e1(octets: &[u8]) -> Result<G1Projective> {
  let bytes: [u8; OCTET_POINT_LENGTH] = octets.try_into().map_err(|_| Error::InvalidLength {
    what: "G1 point",
    expected: OCTET_POINT_LENGTH,
    got: octets.len(),
  })?;
  // `from_compressed` performs the subgroup check; `_unchecked` would not.
  let affine: Option<G1Affine> = G1Affine::from_compressed(&bytes).into();
  affine.map(G1Projective::from).ok_or(Error::InvalidPoint("not a valid compressed G1 point"))
}

/// `octets_to_pubkey(PK)` (draft-08 §4.2.5) — G2, rejecting the identity.
pub fn octets_to_pubkey(pk: &[u8]) -> Result<G2Projective> {
  let bytes: [u8; 96] = pk.try_into().map_err(|_| Error::InvalidLength {
    what: "public key",
    expected: 96,
    got: pk.len(),
  })?;
  let w_opt: Option<G2Affine> = G2Affine::from_compressed(&bytes).into();
  let w = w_opt.ok_or(Error::InvalidPoint("not a valid compressed G2 point"))?;
  if bool::from(w.is_identity()) {
    return Err(Error::InvalidPoint("public key must not be the identity"));
  }
  Ok(G2Projective::from(w))
}

/// A BBS signature: `(A, e)`.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
  pub a: G1Projective,
  pub e: Scalar,
}

impl Signature {
  /// `signature_to_octets` (draft-08 §4.2.4.2).
  pub fn to_octets(&self) -> Vec<u8> {
    serialize(&[Ser::G1(self.a), Ser::Scalar(self.e)])
  }

  /// `octets_to_signature` (draft-08 §4.2.4.3).
  pub fn from_octets(octets: &[u8]) -> Result<Self> {
    let expected = OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH;
    if octets.len() != expected {
      return Err(Error::InvalidLength {
        what: "signature",
        expected,
        got: octets.len(),
      });
    }
    let a = octets_to_point_e1(&octets[..OCTET_POINT_LENGTH])?;
    if bool::from(a.is_identity()) {
      return Err(Error::InvalidPoint("A must not be the identity"));
    }
    let e = scalar_from_be(&octets[OCTET_POINT_LENGTH..])?;
    if bool::from(e.is_zero()) {
      return Err(Error::InvalidScalar("e must be nonzero"));
    }
    Ok(Self { a, e })
  }
}

/// `OS2IP` of exactly 32 octets, rejecting values `>= r`.
///
/// `Scalar::from_be_bytes` returns `None` for a non-canonical encoding,
/// which is exactly the draft's `>= r` rejection.
pub fn scalar_from_be(octets: &[u8]) -> Result<Scalar> {
  let bytes: [u8; OCTET_SCALAR_LENGTH] = octets.try_into().map_err(|_| Error::InvalidLength {
    what: "scalar",
    expected: OCTET_SCALAR_LENGTH,
    got: octets.len(),
  })?;
  let s: Option<Scalar> = Scalar::from_be_bytes(&bytes).into();
  s.ok_or(Error::InvalidScalar("not a canonical scalar (>= r)"))
}

/// The output of `ProofInit` / `ProofVerifyInit`: `(Abar, Bbar, D, T1, T2, domain)`.
#[derive(Clone, Copy, Debug)]
pub struct ProofInitResult {
  pub abar: G1Projective,
  pub bbar: G1Projective,
  pub d: G1Projective,
  pub t1: G1Projective,
  pub t2: G1Projective,
  pub domain: Scalar,
}

/// A deserialized BBS proof.
#[derive(Clone, Debug)]
pub struct Proof {
  pub abar: G1Projective,
  pub bbar: G1Projective,
  pub d: G1Projective,
  pub ehat: Scalar,
  pub r1hat: Scalar,
  pub r3hat: Scalar,
  pub commitments: Vec<Scalar>,
  pub challenge: Scalar,
}

impl Proof {
  pub fn to_octets(&self) -> Vec<u8> {
    let mut items = vec![
      Ser::G1(self.abar),
      Ser::G1(self.bbar),
      Ser::G1(self.d),
      Ser::Scalar(self.ehat),
      Ser::Scalar(self.r1hat),
      Ser::Scalar(self.r3hat),
    ];
    items.extend(self.commitments.iter().map(|c| Ser::Scalar(*c)));
    items.push(Ser::Scalar(self.challenge));
    serialize(&items)
  }

  pub fn from_octets(octets: &[u8]) -> Result<Self> {
    let floor = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH;
    if octets.len() < floor || !(octets.len() - floor).is_multiple_of(OCTET_SCALAR_LENGTH) {
      return Err(Error::InvalidLength {
        what: "proof",
        expected: floor,
        got: octets.len(),
      });
    }
    let mut off = 0;
    let mut take_point = || -> Result<G1Projective> {
      let p = octets_to_point_e1(&octets[off..off + OCTET_POINT_LENGTH])?;
      off += OCTET_POINT_LENGTH;
      if bool::from(p.is_identity()) {
        return Err(Error::InvalidPoint("proof point must not be the identity"));
      }
      Ok(p)
    };
    let abar = take_point()?;
    let bbar = take_point()?;
    let d = take_point()?;

    let n_scalars = (octets.len() - 3 * OCTET_POINT_LENGTH) / OCTET_SCALAR_LENGTH;
    let mut scalars = Vec::with_capacity(n_scalars);
    for i in 0..n_scalars {
      let start = off + i * OCTET_SCALAR_LENGTH;
      scalars.push(scalar_from_be(&octets[start..start + OCTET_SCALAR_LENGTH])?);
    }
    let challenge = *scalars.last().expect("floor guarantees >= 4 scalars");
    Ok(Self {
      abar,
      bbar,
      d,
      ehat: scalars[0],
      r1hat: scalars[1],
      r3hat: scalars[2],
      commitments: scalars[3..scalars.len() - 1].to_vec(),
      challenge,
    })
  }
}

impl Suite {
  /// `calculate_domain(PK, Q_1, H_Points, header, api_id)` (draft-08 §4.2.7).
  pub fn calculate_domain(&self, pk: &[u8], q_1: &G1Projective, h_points: &[G1Projective], header: &[u8]) -> Result<Scalar> {
    let mut dom_array = vec![Ser::U64(h_points.len() as u64), Ser::G1(*q_1)];
    dom_array.extend(h_points.iter().map(|p| Ser::G1(*p)));

    let mut dom_input = pk.to_vec();
    dom_input.extend_from_slice(&serialize(&dom_array));
    dom_input.extend_from_slice(&self.api_id);
    dom_input.extend_from_slice(&i2osp(header.len() as u64, 8));
    dom_input.extend_from_slice(header);

    self.hash_to_scalar(&dom_input, &self.dst(b"H2S_"))
  }

  /// `B = P1 + Q_1 * domain + sum(H_i * msg_i)`, shared by sign/verify/prove.
  fn compute_b(&self, q_1: &G1Projective, h_points: &[G1Projective], messages: &[Scalar], domain: &Scalar) -> Result<G1Projective> {
    Ok(self.p1 + q_1 * domain + sumprod(h_points, messages)?)
  }

  /// `CoreSign` (draft-08 §3.6.1).
  pub fn core_sign(&self, sk: &Scalar, pk: &[u8], generators: &[G1Projective], header: &[u8], messages: &[Scalar]) -> Result<Signature> {
    let l = messages.len();
    if generators.len() != l + 1 {
      return Err(Error::MismatchedLengths {
        what: "messages and generators",
        a: l,
        b: generators.len(),
      });
    }
    let (q_1, h_points) = generators.split_first().expect("length checked above");
    let domain = self.calculate_domain(pk, q_1, h_points, header)?;

    let mut e_items = vec![Ser::Scalar(*sk)];
    e_items.extend(messages.iter().map(|m| Ser::Scalar(*m)));
    e_items.push(Ser::Scalar(domain));
    let e = self.hash_to_scalar(&serialize(&e_items), &self.dst(b"H2S_"))?;

    let b = self.compute_b(q_1, h_points, messages, &domain)?;
    let inv_opt: Option<Scalar> = (sk + e).invert().into();
    let inv = inv_opt.ok_or(Error::InvalidScalar("SK + e is not invertible"))?;
    Ok(Signature { a: b * inv, e })
  }

  /// `CoreVerify` (draft-08 §3.6.2).
  pub fn core_verify(&self, pk: &[u8], signature: &Signature, generators: &[G1Projective], header: &[u8], messages: &[Scalar]) -> Result<()> {
    let w = octets_to_pubkey(pk)?;
    let l = messages.len();
    if generators.len() != l + 1 {
      return Err(Error::MismatchedLengths {
        what: "messages and generators",
        a: l,
        b: generators.len(),
      });
    }
    let (q_1, h_points) = generators.split_first().expect("length checked above");
    let domain = self.calculate_domain(pk, q_1, h_points, header)?;
    let b = self.compute_b(q_1, h_points, messages, &domain)?;

    // e(A, W + G2*e) * e(B, -G2) == 1
    let lhs_g2 = G2Prepared::from(G2Affine::from(w + G2Projective::GENERATOR * signature.e));
    let rhs_g2 = G2Prepared::from(G2Affine::from(-G2Projective::GENERATOR));
    let result = multi_miller_loop(&[(&G1Affine::from(signature.a), &lhs_g2), (&G1Affine::from(b), &rhs_g2)]).final_exponentiation();
    if result != Gt::IDENTITY {
      return Err(Error::VerificationFailed("signature pairing check"));
    }
    Ok(())
  }

  /// `ProofInit` (draft-08 §3.7.1).
  #[allow(clippy::too_many_arguments)]
  pub fn proof_init(
    &self,
    pk: &[u8],
    signature: &Signature,
    generators: &[G1Projective],
    random_scalars: &[Scalar],
    header: &[u8],
    messages: &[Scalar],
    undisclosed_indexes: &[usize],
  ) -> Result<ProofInitResult> {
    let l = messages.len();
    let u = undisclosed_indexes.len();
    if random_scalars.len() != u + 5 {
      return Err(Error::MismatchedLengths {
        what: "random scalars",
        a: random_scalars.len(),
        b: u + 5,
      });
    }
    if generators.len() != l + 1 {
      return Err(Error::MismatchedLengths {
        what: "messages and generators",
        a: l,
        b: generators.len(),
      });
    }
    let (r1, r2, etil, r1til, r3til) = (random_scalars[0], random_scalars[1], random_scalars[2], random_scalars[3], random_scalars[4]);
    let mtilj = &random_scalars[5..];

    let (q_1, h_points) = generators.split_first().expect("length checked above");
    for &i in undisclosed_indexes {
      if i >= l {
        return Err(Error::IndexOutOfRange { index: i, len: l });
      }
    }
    let hj: Vec<G1Projective> = undisclosed_indexes.iter().map(|&j| h_points[j]).collect();

    let domain = self.calculate_domain(pk, q_1, h_points, header)?;
    let b = self.compute_b(q_1, h_points, messages, &domain)?;
    let d = b * r2;
    let abar = signature.a * (r1 * r2);
    let bbar = d * r1 - abar * signature.e;
    let t1 = abar * etil + d * r1til;
    let t2 = d * r3til + sumprod(&hj, mtilj)?;
    Ok(ProofInitResult { abar, bbar, d, t1, t2, domain })
  }

  /// `ProofFinalize` (draft-08 §3.7.2).
  pub fn proof_finalize(
    &self,
    init_res: &ProofInitResult,
    challenge: &Scalar,
    e_value: &Scalar,
    random_scalars: &[Scalar],
    undisclosed_messages: &[Scalar],
  ) -> Result<Proof> {
    let u = undisclosed_messages.len();
    if random_scalars.len() != u + 5 {
      return Err(Error::MismatchedLengths {
        what: "random scalars",
        a: random_scalars.len(),
        b: u + 5,
      });
    }
    let (r1, r2, etil, r1til, r3til) = (random_scalars[0], random_scalars[1], random_scalars[2], random_scalars[3], random_scalars[4]);
    let mtilj = &random_scalars[5..];

    let r3_opt: Option<Scalar> = r2.invert().into();
    let r3 = r3_opt.ok_or(Error::InvalidScalar("r2 is not invertible"))?;
    Ok(Proof {
      abar: init_res.abar,
      bbar: init_res.bbar,
      d: init_res.d,
      ehat: etil + e_value * challenge,
      r1hat: r1til - r1 * challenge,
      r3hat: r3til - r3 * challenge,
      commitments: mtilj.iter().zip(undisclosed_messages.iter()).map(|(mt, m)| mt + m * challenge).collect(),
      challenge: *challenge,
    })
  }

  /// `ProofVerifyInit` (draft-08 §3.7.3).
  pub fn proof_verify_init(
    &self,
    pk: &[u8],
    proof: &Proof,
    generators: &[G1Projective],
    header: &[u8],
    disclosed_messages: &[Scalar],
    disclosed_indexes: &[usize],
  ) -> Result<ProofInitResult> {
    let u = proof.commitments.len();
    let r = disclosed_indexes.len();
    let l = r + u;
    if disclosed_messages.len() != r {
      return Err(Error::MismatchedLengths {
        what: "disclosed messages and indexes",
        a: disclosed_messages.len(),
        b: r,
      });
    }
    for &i in disclosed_indexes {
      if i >= l {
        return Err(Error::IndexOutOfRange { index: i, len: l });
      }
    }
    if generators.len() != l + 1 {
      return Err(Error::MismatchedLengths {
        what: "messages and generators",
        a: l,
        b: generators.len(),
      });
    }
    let undisclosed_indexes: Vec<usize> = (0..l).filter(|j| !disclosed_indexes.contains(j)).collect();

    let (q_1, h_points) = generators.split_first().expect("length checked above");
    let hi: Vec<G1Projective> = disclosed_indexes.iter().map(|&i| h_points[i]).collect();
    let hj: Vec<G1Projective> = undisclosed_indexes.iter().map(|&j| h_points[j]).collect();

    let domain = self.calculate_domain(pk, q_1, h_points, header)?;
    let t1 = proof.bbar * proof.challenge + proof.abar * proof.ehat + proof.d * proof.r1hat;
    let bv = self.p1 + q_1 * domain + sumprod(&hi, disclosed_messages)?;
    let t2 = bv * proof.challenge + proof.d * proof.r3hat + sumprod(&hj, &proof.commitments)?;

    Ok(ProofInitResult {
      abar: proof.abar,
      bbar: proof.bbar,
      d: proof.d,
      t1,
      t2,
      domain,
    })
  }

  /// `ProofChallengeCalculate` (draft-08 §3.7.4).
  pub fn proof_challenge_calculate(&self, init_res: &ProofInitResult, disclosed_messages: &[Scalar], disclosed_indexes: &[usize], ph: &[u8]) -> Result<Scalar> {
    let r = disclosed_indexes.len();
    if disclosed_messages.len() != r {
      return Err(Error::MismatchedLengths {
        what: "disclosed messages and indexes",
        a: disclosed_messages.len(),
        b: r,
      });
    }
    let mut c_arr = vec![Ser::U64(r as u64)];
    for (i, m) in disclosed_indexes.iter().zip(disclosed_messages.iter()) {
      c_arr.push(Ser::U64(*i as u64));
      c_arr.push(Ser::Scalar(*m));
    }
    c_arr.extend([
      Ser::G1(init_res.abar),
      Ser::G1(init_res.bbar),
      Ser::G1(init_res.d),
      Ser::G1(init_res.t1),
      Ser::G1(init_res.t2),
      Ser::Scalar(init_res.domain),
    ]);
    let mut c_octs = serialize(&c_arr);
    c_octs.extend_from_slice(&i2osp(ph.len() as u64, 8));
    c_octs.extend_from_slice(ph);
    self.hash_to_scalar(&c_octs, &self.dst(b"H2S_"))
  }

  // ---- Top-level API (draft-08 §3.5) --------------------------------

  /// `Sign(SK, PK, header, messages)`.
  pub fn sign(&self, sk: &Scalar, pk: &[u8], header: &[u8], messages: &[Vec<u8>]) -> Result<Vec<u8>> {
    let message_scalars = self.messages_to_scalars(messages)?;
    let generators = self.create_generators(messages.len() + 1)?;
    Ok(self.core_sign(sk, pk, &generators, header, &message_scalars)?.to_octets())
  }

  /// `Verify(PK, signature, header, messages)`.
  pub fn verify(&self, pk: &[u8], signature: &[u8], header: &[u8], messages: &[Vec<u8>]) -> Result<()> {
    let sig = Signature::from_octets(signature)?;
    let message_scalars = self.messages_to_scalars(messages)?;
    let generators = self.create_generators(messages.len() + 1)?;
    self.core_verify(pk, &sig, &generators, header, &message_scalars)
  }
}
