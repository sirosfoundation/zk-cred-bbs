// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Cipher suite parameters for `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`
//! (draft-irtf-cfrg-bbs-signatures-08 §6.2.1) and the random-scalar source.

use bls12_381_plus::elliptic_curve_013::hash2curve::ExpandMsgXmd;
use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::util::{expand_message_xmd, i2osp, os2ip_48_mod_r};

/// Base cipher suite id.
pub const SUITE_ID: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// The BBS `api_id` = suite id || "H2G_HM2S_".
pub const API_ID: &str = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";

/// `octet_scalar_length` — width of a serialized scalar.
pub const OCTET_SCALAR_LENGTH: usize = 32;
/// `octet_point_length` — width of a compressed G1 point.
pub const OCTET_POINT_LENGTH: usize = 48;
/// `expand_len` — uniform-bytes width fed to `OS2IP ... mod r`.
pub const EXPAND_LEN: usize = 48;

/// The fixed generator `P1` for this suite (draft-08 §6.2.1).
pub const P1_COMPRESSED: [u8; 48] = [
  0xa8, 0xce, 0x25, 0x61, 0x02, 0x84, 0x08, 0x21, 0xa3, 0xe9, 0x4e, 0xa9, 0x02, 0x5e, 0x46, 0x62, 0xb2, 0x05, 0x76, 0x2f, 0x97, 0x76, 0xb3, 0xa7, 0x66, 0xc8,
  0x72, 0xb9, 0x48, 0xf1, 0xfd, 0x22, 0x5e, 0x7c, 0x59, 0x69, 0x85, 0x88, 0xe7, 0x0d, 0x11, 0x40, 0x6d, 0x16, 0x1b, 0x4e, 0x28, 0xc9,
];

/// Where random scalars come from.
///
/// The `Seeded` variant is not a convenience: the CFRG drafts' own test
/// vectors — and Emil's hardware key binding vector, whose device
/// signatures are fixed constants — are only reproducible with a
/// deterministic scalar stream. Verification never needs randomness, so a
/// verifier-only build can ignore this entirely.
#[derive(Clone, Debug)]
pub enum ScalarSource {
  /// Real randomness. The only correct choice in production.
  System,
  /// `seeded_random_scalars` (draft-08 §7.1.1) — TEST USE ONLY.
  Seeded { seed: Vec<u8>, dst: Vec<u8> },
}

impl ScalarSource {
  /// The same source, for a retry.
  ///
  /// [`System`](ScalarSource::System) is unchanged - it is already fresh
  /// on every call. [`Seeded`](ScalarSource::Seeded) is not: it is a pure
  /// function of `(seed, dst, count)`, so re-drawing from it returns the
  /// *identical* scalar. Any algorithm that retries on a rejected draw
  /// therefore cannot make progress against a seeded source unless the
  /// attempt number is mixed in, which is what this does.
  ///
  /// Attempt 0 returns the source unchanged, so existing vectors and the
  /// drafts' own reproduce byte for byte.
  pub fn for_attempt(&self, attempt: usize) -> Self {
    match self {
      ScalarSource::System => ScalarSource::System,
      ScalarSource::Seeded { seed, dst } if attempt == 0 => ScalarSource::Seeded {
        seed: seed.clone(),
        dst: dst.clone(),
      },
      ScalarSource::Seeded { seed, dst } => ScalarSource::Seeded {
        seed: seed.clone(),
        dst: [dst.as_slice(), b"_RETRY_", attempt.to_be_bytes().as_slice()].concat(),
      },
    }
  }

  /// `calculate_random_scalars(count)`.
  pub fn calculate(&self, count: usize) -> Result<Vec<Scalar>> {
    match self {
      ScalarSource::System => (0..count)
        .map(|_| {
          let mut buf = [0u8; EXPAND_LEN];
          getrandom::fill(&mut buf).map_err(|e| Error::SignerFailed(format!("rng failure: {e}")))?;
          os2ip_48_mod_r(&buf)
        })
        .collect(),
      ScalarSource::Seeded { seed, dst } => {
        let out_len = EXPAND_LEN * count;
        if out_len > 65536 {
          return Err(Error::TooMany("seeded random scalars"));
        }
        let v = expand_message_xmd(seed, dst, out_len)?;
        (0..count).map(|i| os2ip_48_mod_r(&v[i * EXPAND_LEN..(i + 1) * EXPAND_LEN])).collect()
      }
    }
  }
}

/// The DSTs `create_generators` derives its seed and points from.
///
/// Overridable only because the drafts' own generator test vectors use
/// non-default values; production always wants [`GeneratorDsts::default`].
#[derive(Clone, Debug)]
pub struct GeneratorDsts {
  pub sig_generator_seed: Vec<u8>,
  pub sig_generator_dst: Vec<u8>,
  pub message_generator_seed: Vec<u8>,
}

impl Default for GeneratorDsts {
  fn default() -> Self {
    Self {
      sig_generator_seed: b"SIG_GENERATOR_SEED_".to_vec(),
      sig_generator_dst: b"SIG_GENERATOR_DST_".to_vec(),
      message_generator_seed: b"MESSAGE_GENERATOR_SEED".to_vec(),
    }
  }
}

/// A configured BBS cipher suite.
#[derive(Clone, Debug)]
pub struct Suite {
  pub api_id: Vec<u8>,
  pub p1: G1Projective,
  pub generator_dsts: GeneratorDsts,
  pub scalars: ScalarSource,
}

impl Default for Suite {
  fn default() -> Self {
    Self::new(ScalarSource::System)
  }
}

impl Suite {
  pub fn new(scalars: ScalarSource) -> Self {
    let p1 = G1Affine::from_compressed(&P1_COMPRESSED).expect("P1 constant is a valid compressed G1 point");
    Self {
      api_id: API_ID.as_bytes().to_vec(),
      p1: G1Projective::from(p1),
      generator_dsts: GeneratorDsts::default(),
      scalars,
    }
  }

  /// `api_id || suffix`, the shape every BBS DST takes.
  pub fn dst(&self, suffix: &[u8]) -> Vec<u8> {
    let mut v = self.api_id.clone();
    v.extend_from_slice(suffix);
    v
  }

  /// `hash_to_scalar(msg_octets, dst)` (draft-08 §4.2.2).
  pub fn hash_to_scalar(&self, msg: &[u8], dst: &[u8]) -> Result<Scalar> {
    os2ip_48_mod_r(&expand_message_xmd(msg, dst, EXPAND_LEN)?)
  }

  /// `messages_to_scalars(messages, api_id)` (draft-08 §4.2.3).
  pub fn messages_to_scalars(&self, messages: &[Vec<u8>]) -> Result<Vec<Scalar>> {
    let dst = self.dst(b"MAP_MSG_TO_SCALAR_AS_HASH_");
    messages.iter().map(|m| self.hash_to_scalar(m, &dst)).collect()
  }

  /// `create_generators(count, api_id)` (draft-08 §4.2.1).
  pub fn create_generators(&self, count: usize) -> Result<Vec<G1Projective>> {
    let d = &self.generator_dsts;
    let mut seed_dst = self.api_id.clone();
    seed_dst.extend_from_slice(&d.sig_generator_seed);
    let mut generator_dst = self.api_id.clone();
    generator_dst.extend_from_slice(&d.sig_generator_dst);
    let mut generator_seed = self.api_id.clone();
    generator_seed.extend_from_slice(&d.message_generator_seed);

    let mut v = expand_message_xmd(&generator_seed, &seed_dst, EXPAND_LEN)?;
    let mut out = Vec::with_capacity(count);
    for i in 1..=count {
      let mut input = v.clone();
      input.extend_from_slice(&i2osp(i as u64, 8));
      v = expand_message_xmd(&input, &seed_dst, EXPAND_LEN)?;
      out.push(G1Projective::hash::<ExpandMsgXmd<Sha256>>(&v, &generator_dst));
    }
    Ok(out)
  }
}
