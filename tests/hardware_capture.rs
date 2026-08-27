// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Conformance against values captured from a real YubiKey 5.8.1-alpha0,
//! supplied by Emil Lundberg 2026-08-27.
//!
//! `test-vectors/emlun_reference.json` proves this port agrees with the
//! TypeScript reference on data hardware produced, but it contains exactly
//! one operation with one message. That cannot distinguish an
//! implementation that is correct from one that happens to agree on a
//! single input. These are three signatures over three different messages
//! from the same key handle, plus the `generateKey` response verbatim.

use bls12_381_plus::{G1Affine, G1Projective};
use num_bigint::BigUint;
use zk_cred_bbs::keybind::{SchnorrBls12381, SignatureScheme};

/// COSE `-2`, the x coordinate as the authenticator reports it.
const COSE_X: &str = "034afe67442f9e3be5db11617ad616f11daa37f4eb649602953779c5c7a0c47f8e925bda6dd42bf6034704e43f5ebafa";
/// COSE `-3`, the y coordinate.
const COSE_Y: &str = "0de0727387be67502d02bf70a2bef0618d2b3af718a259b4e1ffab748f52f98bb6292bb3093fa74dbee33763151b3781";
/// The `bbsAdjustedPublicKey` the client surfaces alongside the COSE key.
const ADJUSTED: &str = "834afe67442f9e3be5db11617ad616f11daa37f4eb649602953779c5c7a0c47f8e925bda6dd42bf6034704e43f5ebafa";

const CAPTURES: &[(&str, &str)] = &[
  (
    "249ba0a0f433309d98c9d8a27d2681868e343eee1e721b669b1eef41e8c5d72a",
    "4b520293a4dc9b75cd18823262a6da8732aac52df01534af33cd318a750874c267db5fe08e966f321687cad92b1cb6f6b17787b9eba3ec52c7581eda47796e20",
  ),
  (
    "4082f01f71ffdacd7c571c37a70dacaf08dd206c6d35323fe427ad1ccb62e03a",
    "1986ff08328ab0d9b1a79e29ca7a303f5b4b26addc40ca239c1162c126d23d1763591381e228e524a7f8db30ebc9f4dfb1abb943635f1b63c9cf1efeeaaa4014",
  ),
  (
    "d9c948d82f842f4b21d183a1d874fddbb071521691fd9fbbb0f7500117adfc93",
    "4aa49cd718e74b77a024ed1570081fddec376ca6d01dd72a5d0f6d0f5492e252422d70bea0e2def38f97352b3209b6561f9b0f3f1492ff1e27fbf0b64ebb8431",
  ),
];

fn unhex(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex")
}

fn adjusted_point() -> G1Affine {
  let mut c = [0u8; 48];
  c.copy_from_slice(&unhex(ADJUSTED));
  Option::from(G1Affine::from_compressed(&c)).expect("bbsAdjustedPublicKey is a valid G1 point")
}

/// Two facts about the authenticator's key, both easy to get wrong.
///
/// 1. It is reported as an **EC2-style pair of 48-byte coordinates** at
///    COSE `-2`/`-3`, not as a single compressed point. A decoder that read
///    `-2` alone and treated those 48 bytes as the compressed form would get
///    a value that is *almost* right - same length, same leading bytes -
///    and fail only much later, at verification, with nothing to point at.
///
/// 2. `bbsAdjustedPublicKey` is not merely that point compressed: it is the
///    compression of its **negation**. The x coordinate is identical and
///    the two y values sum to the field modulus. That is DELTA 4's sign
///    conversion, pre-applied - so the "adjusted" key is the one already in
///    this crate's convention, and negating it again (as an earlier draft
///    of this test did) gets you back to the authenticator's.
#[test]
fn adjusted_public_key_is_the_negation_of_the_cose_coordinates() {
  let uncompressed = adjusted_point().to_uncompressed();
  assert_eq!(hex::encode(&uncompressed[..48]), COSE_X, "x is unchanged by negation");
  assert_ne!(hex::encode(&uncompressed[48..]), COSE_Y, "y must differ - if it matched, no negation happened");

  // -y == p - y, so the two y values sum to the modulus.
  let p = BigUint::parse_bytes(
    b"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
  )
  .unwrap();
  let y_cose = BigUint::from_bytes_be(&unhex(COSE_Y));
  let y_adj = BigUint::from_bytes_be(&uncompressed[48..]);
  assert_eq!(y_cose + y_adj, p, "the two y coordinates must sum to the field modulus");
}

/// Three signatures, three different messages, one key handle - verified
/// against this crate's own Schnorr implementation.
///
/// This is what a single captured vector cannot do. An implementation that
/// agreed with hardware on one input by coincidence fails here.
#[test]
fn hardware_signatures_verify_over_three_different_messages() {
  let scheme = SchnorrBls12381;
  let hk = G1Projective::GENERATOR;
  // DELTA 4: the authenticator's key follows the RFC 8235 sign
  // convention and this crate follows eprint 2025/1995, so the key has to
  // be negated - but `bbsAdjustedPublicKey` already is the negation, so it
  // is used as-is here. Negating it again would undo the adjustment.
  let pk = G1Projective::from(adjusted_point());

  for (i, (tbs, sig)) in CAPTURES.iter().enumerate() {
    scheme
      .verify(&hk, &pk, &unhex(sig), &unhex(tbs))
      .unwrap_or_else(|e| panic!("capture {i} failed to verify: {e}"));
  }
}

/// The sign conversion is not cosmetic: the authenticator's own key, used
/// unconverted, verifies none of these. Pinning that here means a change to
/// the convention shows up as a failing test rather than as proofs that
/// silently stop verifying.
#[test]
fn the_raw_authenticator_key_does_not_verify() {
  let scheme = SchnorrBls12381;
  let hk = G1Projective::GENERATOR;
  // Negating the adjusted key recovers the authenticator's own.
  let un_negated = -G1Projective::from(adjusted_point());

  for (i, (tbs, sig)) in CAPTURES.iter().enumerate() {
    assert!(
      scheme.verify(&hk, &un_negated, &unhex(sig), &unhex(tbs)).is_err(),
      "capture {i} verified under the authenticator's own sign convention - DELTA 4 may have changed"
    );
  }
}

/// The crate's own helper must turn the authenticator's reported
/// coordinates into exactly the key that verifies those signatures - the
/// whole point of it existing rather than leaving callers to do it.
#[test]
fn the_helper_reproduces_the_adjusted_key_from_the_cose_coordinates() {
  let derived = zk_cred_bbs::keybind::keybind_public_key_from_coordinates(&unhex(COSE_X), &unhex(COSE_Y)).expect("real authenticator coordinates must convert");
  assert_eq!(hex::encode(&derived), ADJUSTED);

  // And it verifies real signatures, not just matches a constant.
  let scheme = SchnorrBls12381;
  let mut c = [0u8; 48];
  c.copy_from_slice(&derived);
  let pk = G1Projective::from(Option::<G1Affine>::from(G1Affine::from_compressed(&c)).expect("valid point"));
  for (tbs, sig) in CAPTURES {
    scheme
      .verify(&G1Projective::GENERATOR, &pk, &unhex(sig), &unhex(tbs))
      .expect("helper output must verify hardware signatures");
  }
}

#[test]
fn the_helper_rejects_malformed_coordinates() {
  use zk_cred_bbs::keybind::keybind_public_key_from_coordinates as convert;
  let x = unhex(COSE_X);
  let y = unhex(COSE_Y);

  assert!(convert(&x[..47], &y).is_err(), "short x");
  assert!(convert(&x, &y[..47]).is_err(), "short y");
  // A caller passing the already-compressed form by mistake: the flag bits
  // are set, so it is not a bare coordinate.
  assert!(convert(&unhex(ADJUSTED), &y).is_err(), "compressed point as x");
  // Valid-length coordinates that are not on the curve.
  assert!(convert(&[0u8; 48], &[0u8; 48]).is_err(), "not on the curve");
}

/// Each capture is a distinct message, so the suite genuinely exercises
/// more than one input.
#[test]
fn the_captures_are_actually_distinct() {
  for i in 1..CAPTURES.len() {
    assert_ne!(CAPTURES[i].0, CAPTURES[0].0);
    assert_ne!(CAPTURES[i].1, CAPTURES[0].1);
  }
  // Every signed message is a 32-octet challenge, matching the profile.
  for (tbs, sig) in CAPTURES {
    assert_eq!(unhex(tbs).len(), 32);
    assert_eq!(unhex(sig).len(), 64);
  }
}
