// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Issuer key generation (draft-irtf-cfrg-bbs-signatures-08 §3.4.1).
//!
//! # Why this exists
//!
//! Until this module, nothing in this crate — or in any of its bindings, or
//! in the Go package that wraps them — could produce a BBS key pair. The
//! only one in existence anywhere in the stack was the reference test
//! vector, which is not a thing to run an issuer on. An issuer that cannot
//! be given a key cannot issue, so this is not a convenience.
//!
//! # Why the secret key is not a signer handle
//!
//! Every other issuer key in this organisation's stack is an ECDSA key that
//! signs a digest, and can therefore live behind PKCS#11 in an HSM. A BBS
//! secret key cannot: it is a BLS12-381 scalar consumed *inside* the
//! signing algebra, and mainstream HSMs do not implement the curve. So it
//! is bytes, it is software-held, and [`key_gen`] returns it as such. That
//! is a known and accepted property of the format rather than an oversight
//! to fix later.

use bls12_381_plus::group::Curve;
use bls12_381_plus::{G2Projective, Scalar};

use crate::error::{Error, Result};
use crate::suite::{OCTET_SCALAR_LENGTH, Suite};
use crate::util::i2osp;

/// `key_dst` default suffix — `api_id || "KEYGEN_DST_"` (§3.4.1).
const KEYGEN_DST_SUFFIX: &[u8] = b"KEYGEN_DST_";

/// Minimum `key_material` width the specification allows.
///
/// A hard floor rather than a recommendation: the secret key is derived
/// deterministically from this input, so its entropy is the entropy of the
/// resulting key. Deriving a BLS12-381 scalar from fewer than 32 octets
/// produces a key that looks the right width and is not.
pub const MIN_KEY_MATERIAL_LEN: usize = 32;

/// Maximum `key_info` width — it is length-prefixed with two octets.
pub const MAX_KEY_INFO_LEN: usize = 65535;

/// Width of a compressed G2 point, which is what a BBS public key is.
pub const OCTET_PUBKEY_LENGTH: usize = 96;

/// `KeyGen(key_material, key_info, key_dst)` (§3.4.1).
///
/// Deterministic in all three inputs: the same `key_material` and
/// `key_info` always yield the same key. That is the specification's
/// design, and it is what makes a key reproducible from a backed-up seed
/// rather than only from a backed-up key.
///
/// # Arguments
///
/// * `key_material` — secret input, at least [`MIN_KEY_MATERIAL_LEN`]
///   octets, from a cryptographically secure source.
/// * `key_info` — optional context bound into the derivation, so one
///   `key_material` can yield distinct keys for distinct purposes.
/// * `key_dst` — domain separation tag; `None` uses the suite default.
pub fn key_gen(key_material: &[u8], key_info: &[u8], key_dst: Option<&[u8]>) -> Result<Scalar> {
  if key_material.len() < MIN_KEY_MATERIAL_LEN {
    return Err(Error::InvalidLength {
      what: "key_material",
      expected: MIN_KEY_MATERIAL_LEN,
      got: key_material.len(),
    });
  }
  if key_info.len() > MAX_KEY_INFO_LEN {
    return Err(Error::InvalidLength {
      what: "key_info",
      expected: MAX_KEY_INFO_LEN,
      got: key_info.len(),
    });
  }

  let suite = Suite::default();
  let dst = key_dst.map(<[u8]>::to_vec).unwrap_or_else(|| suite.dst(KEYGEN_DST_SUFFIX));

  let mut derive_input = key_material.to_vec();
  derive_input.extend_from_slice(&i2osp(key_info.len() as u64, 2));
  derive_input.extend_from_slice(key_info);

  let sk = suite.hash_to_scalar(&derive_input, &dst)?;

  // The specification says to fail rather than retry. A zero scalar here
  // means the derivation produced a key that signs nothing verifiable, and
  // silently drawing again would hide that the input was the problem.
  if bool::from(<Scalar as bls12_381_plus::ff::Field>::is_zero(&sk)) {
    return Err(Error::InvalidPoint("KeyGen produced a zero secret key"));
  }

  Ok(sk)
}

/// Generate a key pair from fresh system randomness.
///
/// Returns `(SK, PK)` already serialised, in the widths the rest of this
/// stack reads: 32 octets big-endian for the scalar, 96 for the compressed
/// G2 point.
pub fn key_gen_random(key_info: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
  let mut key_material = [0u8; MIN_KEY_MATERIAL_LEN];
  getrandom::fill(&mut key_material).map_err(|e| Error::SignerFailed(format!("rng failure: {e}")))?;
  let sk = key_gen(&key_material, key_info, None)?;
  Ok((sk_to_octets(&sk), sk_to_pk(&sk)))
}

/// `SkToPk(SK)` (§3.4.2) — the compressed G2 point `SK * BP2`.
pub fn sk_to_pk(sk: &Scalar) -> Vec<u8> {
  (G2Projective::GENERATOR * sk).to_affine().to_compressed().to_vec()
}

/// The secret scalar as the 32 big-endian octets everything else reads.
pub fn sk_to_octets(sk: &Scalar) -> Vec<u8> {
  sk.to_be_bytes().to_vec()
}

/// Recover the public key from a serialised secret key.
///
/// This is what lets a holder of a key *pair* check the two halves belong
/// together. Signing with a mismatched pair produces credentials that fail
/// at every relying party, reporting only "does not verify" — a failure
/// mode with nothing in it pointing at the configuration.
pub fn public_key_for(sk_octets: &[u8]) -> Result<Vec<u8>> {
  let bytes: [u8; OCTET_SCALAR_LENGTH] = sk_octets.try_into().map_err(|_| Error::InvalidLength {
    what: "secret key",
    expected: OCTET_SCALAR_LENGTH,
    got: sk_octets.len(),
  })?;
  let sk_opt: Option<Scalar> = Scalar::from_be_bytes(&bytes).into();
  let sk = sk_opt.ok_or(Error::InvalidPoint("secret key is not a canonical scalar"))?;
  if bool::from(<Scalar as bls12_381_plus::ff::Field>::is_zero(&sk)) {
    return Err(Error::InvalidPoint("secret key must not be zero"));
  }
  Ok(sk_to_pk(&sk))
}

/// Whether a serialised key pair really is a pair.
pub fn key_pair_matches(sk_octets: &[u8], pk_octets: &[u8]) -> Result<()> {
  if pk_octets.len() != OCTET_PUBKEY_LENGTH {
    return Err(Error::InvalidLength {
      what: "public key",
      expected: OCTET_PUBKEY_LENGTH,
      got: pk_octets.len(),
    });
  }
  if public_key_for(sk_octets)? != pk_octets {
    return Err(Error::InvalidPoint("public key does not belong to this secret key"));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Ground truth, not self-consistency.
  ///
  /// `emlun_reference.json` carries a `(sk, pk)` pair produced by a
  /// separate implementation. If `SkToPk` here lands on the same 96 octets,
  /// this agrees with that implementation about what a public key *is* —
  /// which is the half of key handling that a verifier depends on.
  #[test]
  fn sk_to_pk_matches_the_reference_implementation() {
    let raw = match std::fs::read_to_string("test-vectors/emlun_reference.json") {
      Ok(raw) => raw,
      Err(e) => {
        eprintln!("reference vectors not staged: {e}");
        return;
      }
    };
    let v: serde_json::Value = serde_json::from_str(&raw).expect("vectors parse");
    let sk = hex_decode(v["sign"]["sk"].as_str().expect("sk"));
    let pk = hex_decode(v["sign"]["pk"].as_str().expect("pk"));

    assert_eq!(sk.len(), OCTET_SCALAR_LENGTH);
    assert_eq!(pk.len(), OCTET_PUBKEY_LENGTH);
    assert_eq!(public_key_for(&sk).expect("derive"), pk, "SkToPk disagrees with the reference");
    key_pair_matches(&sk, &pk).expect("the reference pair must validate as a pair");
  }

  /// The whole point of a pair check is that it says no.
  #[test]
  fn a_mismatched_pair_is_rejected() {
    let (sk_a, _) = key_gen_random(b"").expect("a");
    let (_, pk_b) = key_gen_random(b"").expect("b");
    assert!(key_pair_matches(&sk_a, &pk_b).is_err(), "two unrelated halves must not validate");
  }

  /// Deterministic in `key_material`, and separated by `key_info` — both
  /// are properties an operator relies on when re-deriving a key from a
  /// backed-up seed rather than a backed-up key.
  #[test]
  fn derivation_is_deterministic_and_key_info_separates() {
    let material = [7u8; 32];
    let a = key_gen(&material, b"issuer-1", None).expect("a");
    let again = key_gen(&material, b"issuer-1", None).expect("again");
    let other = key_gen(&material, b"issuer-2", None).expect("other");

    assert_eq!(sk_to_octets(&a), sk_to_octets(&again), "same inputs must give the same key");
    assert_ne!(sk_to_octets(&a), sk_to_octets(&other), "key_info must separate keys");
  }

  /// Short key material is refused rather than stretched.
  ///
  /// The derivation would happily produce a well-formed scalar from 8
  /// octets, and it would have 8 octets of entropy while looking exactly
  /// like a 32-octet key.
  #[test]
  fn key_material_below_the_floor_is_refused() {
    assert!(key_gen(&[1u8; 31], b"", None).is_err());
    assert!(key_gen(&[1u8; 32], b"", None).is_ok());
  }

  #[test]
  fn a_random_pair_round_trips() {
    let (sk, pk) = key_gen_random(b"test").expect("keygen");
    assert_eq!(sk.len(), OCTET_SCALAR_LENGTH);
    assert_eq!(pk.len(), OCTET_PUBKEY_LENGTH);
    key_pair_matches(&sk, &pk).expect("a freshly generated pair must validate");
    // And it is actually usable as an issuer key.
    crate::bbs::octets_to_pubkey(&pk).expect("the public key must parse as a G2 point");
  }

  #[test]
  fn two_random_keys_differ() {
    let (a, _) = key_gen_random(b"").expect("a");
    let (b, _) = key_gen_random(b"").expect("b");
    assert_ne!(a, b, "key_gen_random must not be deterministic");
  }

  fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
  }
}
