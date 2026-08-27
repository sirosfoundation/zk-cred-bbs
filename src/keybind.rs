// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Key binding signature schemes.
//!
//! This is the seam where the device-binding construction is chosen. Today
//! there is one real instance — [`SchnorrBls12381`], the construction Emil
//! Lundberg's YubiKey prototype implements — plus [`NullScheme`] for
//! credentials with no device binding. A future `ecdsa-p256-db` (Lehmann)
//! instance would slot in here, though note it also implies a different
//! credential message layout, not only a different signature algorithm; see
//! `PROFILE.md` §4.
//!
//! **`SchnorrBls12381` carries three deliberate deviations** from the base
//! BBS conventions, all of them accommodations to prototype authenticator
//! firmware. They are documented per-item in `PROFILE.md` §3 and marked
//! `DELTA n` in the code below.

use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use sha2::{Digest, Sha256};

use crate::bbs::{Ser, scalar_from_be, serialize};
use crate::error::{Error, Result};
use crate::suite::{OCTET_SCALAR_LENGTH, ScalarSource};

/// One key binding signature scheme.
///
/// `sign` is only used for software-held key binding keys (tests, and
/// platforms with no BLS-capable authenticator). A hardware key binding key
/// never calls it: the wallet obtains the signature from the authenticator
/// and passes the raw bytes to `*Finalize`.
pub trait SignatureScheme {
  /// Serialized signature width, needed to parse commitments and proofs.
  fn signature_length(&self) -> usize;

  /// Generate a key pair on the given generator. Software keys only.
  fn key_gen(&self, hk: &G1Projective, scalars: &ScalarSource) -> Result<(Scalar, G1Projective)>;

  /// Sign `message` under `sk` on generator `hk`. Software keys only.
  fn sign(&self, hk: &G1Projective, sk: &Scalar, message: &[u8], scalars: &ScalarSource) -> Result<Vec<u8>>;

  /// Verify `sig` over `message` against `pk` on generator `hk`.
  fn verify(&self, hk: &G1Projective, pk: &G1Projective, sig: &[u8], message: &[u8]) -> Result<()>;

  /// Re-randomize a signature so it verifies against the blinded public
  /// key `pk + hk * r_key`, without the signer's involvement.
  ///
  /// This is what buys unlinkability: the device signs once under its
  /// stable key, and the wallet adapts that signature to a fresh
  /// randomized key for each presentation.
  fn adapt_sig(&self, sig: &[u8], r_key: &Scalar, message: &[u8]) -> Result<Vec<u8>>;
}

/// No key binding. Every operation is an error; used when `K == 0`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullScheme;

impl SignatureScheme for NullScheme {
  fn signature_length(&self) -> usize {
    0
  }
  fn key_gen(&self, _: &G1Projective, _: &ScalarSource) -> Result<(Scalar, G1Projective)> {
    Err(Error::Unsupported("key binding is not enabled for this suite"))
  }
  fn sign(&self, _: &G1Projective, _: &Scalar, _: &[u8], _: &ScalarSource) -> Result<Vec<u8>> {
    Err(Error::Unsupported("key binding is not enabled for this suite"))
  }
  fn verify(&self, _: &G1Projective, _: &G1Projective, _: &[u8], _: &[u8]) -> Result<()> {
    Err(Error::Unsupported("key binding is not enabled for this suite"))
  }
  fn adapt_sig(&self, _: &[u8], _: &Scalar, _: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Unsupported("key binding is not enabled for this suite"))
  }
}

/// Builds a key binding public key from the coordinates an authenticator
/// reports, applying the sign conversion (`PROFILE.md` DELTA 4).
///
/// The YubiKey previewSign `generateKey` output carries the public key as an
/// **EC2-style pair of 48-octet coordinates** at COSE `-2`/`-3` - not as a
/// single compressed point. And it follows RFC 8235's sign convention while
/// this crate follows eprint 2025/1995's, so the point must be negated
/// before it is usable as a key binding key.
///
/// Both steps are easy to get wrong in ways that stay silent until a proof
/// fails to verify, which is why this is a named function rather than a
/// note for callers to follow:
///
/// * reading `-2` alone and treating those 48 octets as a compressed point
///   yields something that is *almost* right - correct length, same leading
///   bytes - and fails only at verification;
/// * skipping the negation yields a key that is a perfectly valid point,
///   just not the one that verifies anything.
///
/// Verified against a real 5.8.1-alpha0 capture in
/// `tests/hardware_capture.rs`.
pub fn keybind_public_key_from_coordinates(x: &[u8], y: &[u8]) -> Result<Vec<u8>> {
  let (x, y): ([u8; 48], [u8; 48]) = (
    x.try_into().map_err(|_| Error::InvalidLength {
      what: "x coordinate",
      expected: 48,
      got: x.len(),
    })?,
    y.try_into().map_err(|_| Error::InvalidLength {
      what: "y coordinate",
      expected: 48,
      got: y.len(),
    })?,
  );

  // `from_uncompressed` expects the Zcash layout: x || y with the flag
  // bits living in x's top three. The authenticator reports bare
  // coordinates, so those bits must be clear or this is not the encoding
  // we think it is.
  if x[0] & 0xe0 != 0 {
    return Err(Error::InvalidPoint("x coordinate has flag bits set; expected a bare coordinate"));
  }
  let mut uncompressed = [0u8; 96];
  uncompressed[..48].copy_from_slice(&x);
  uncompressed[48..].copy_from_slice(&y);

  let affine: Option<G1Affine> = G1Affine::from_uncompressed(&uncompressed).into();
  let affine = affine.ok_or(Error::InvalidPoint("coordinates are not a valid G1 point on the curve"))?;

  // DELTA 4.
  Ok(G1Affine::from(-G1Projective::from(affine)).to_compressed().to_vec())
}

/// Schnorr over BLS12-381 G1, in the formulation of eprint 2025/1995
/// (`s = ω + c·sk`, verified as `R = s·H0 − c·pk`).
///
/// This is the scheme the YubiKey prototype implements as COSE algorithm
/// `-65609` (`EcsdsaBls12_381_BP1_Sha256_SEC1`, a placeholder identifier).
#[derive(Clone, Copy, Debug, Default)]
pub struct SchnorrBls12381;

impl SchnorrBls12381 {
  /// **DELTA 2** — the nonce point is hashed in SEC1 *uncompressed* form
  /// (`0x04 || x || y`, 97 octets), not BBS's own 48-octet Zcash-compact
  /// encoding, because that is what the authenticator firmware hashes.
  fn serialize_nonce_point(r: &G1Projective) -> Vec<u8> {
    let affine = G1Affine::from(r);
    // `to_uncompressed()` is x || y, both big-endian, without the SEC1
    // tag byte — so the tag is prepended here.
    let mut out = Vec::with_capacity(97);
    out.push(0x04);
    out.extend_from_slice(&affine.to_uncompressed());
    out
  }

  /// `OS2IP(SHA-256(msg))`, unreduced.
  ///
  /// Deliberately *not* reduced mod r: signing retries with a fresh nonce
  /// when the result is out of range (see [`SignatureScheme::sign`]), which
  /// is only meaningful if the value can be out of range in the first
  /// place. Returns `None` when `>= r`.
  fn challenge_hash(msg: &[u8]) -> Option<Scalar> {
    let digest: [u8; 32] = Sha256::digest(msg).into();
    Option::from(Scalar::from_be_bytes(&digest))
  }

  /// `SHA-256(OS2IP(...))` reduced mod r — the verifier's side, where the
  /// parsed `c` is already known to be in range so reduction is a no-op
  /// for honestly generated signatures.
  fn challenge_hash_reduced(msg: &[u8]) -> Scalar {
    let digest: [u8; 32] = Sha256::digest(msg).into();
    let mut wide = [0u8; 64];
    // from_bytes_wide takes little-endian; reverse the big-endian digest
    // into the low half.
    for (i, b) in digest.iter().rev().enumerate() {
      wide[i] = *b;
    }
    Scalar::from_bytes_wide(&wide)
  }

  fn parse(sig: &[u8]) -> Result<(Scalar, Scalar)> {
    if sig.len() != 2 * OCTET_SCALAR_LENGTH {
      return Err(Error::InvalidLength {
        what: "key binding signature",
        expected: 2 * OCTET_SCALAR_LENGTH,
        got: sig.len(),
      });
    }
    let s = scalar_from_be(&sig[..OCTET_SCALAR_LENGTH])?;
    let c = scalar_from_be(&sig[OCTET_SCALAR_LENGTH..])?;
    Ok((s, c))
  }
}

impl SignatureScheme for SchnorrBls12381 {
  fn signature_length(&self) -> usize {
    2 * OCTET_SCALAR_LENGTH
  }

  fn key_gen(&self, hk: &G1Projective, scalars: &ScalarSource) -> Result<(Scalar, G1Projective)> {
    let sk = scalars.calculate(1)?[0];
    Ok((sk, hk * sk))
  }

  fn sign(&self, hk: &G1Projective, sk: &Scalar, message: &[u8], scalars: &ScalarSource) -> Result<Vec<u8>> {
    // Bounded retry: an attempt fails when SHA-256 lands on a value >= r.
    // That is NOT rare - r is about 0.453 * 2^256, so roughly 55% of
    // attempts are rejected, and 64 of them all failing has probability
    // ~1.7e-17. A loop that could in principle run forever is not
    // something to ship.
    //
    // `for_attempt` is what makes the retry mean anything against a
    // deterministic scalar source: without it every attempt re-draws the
    // identical nonce, so a seeded source could not sign the ~55% of
    // (key, message) pairs whose first attempt is rejected.
    for attempt in 0..64 {
      let scalars = &scalars.for_attempt(attempt);
      let k_tilde = scalars.calculate(1)?[0];
      let r = hk * k_tilde;
      let mut input = Self::serialize_nonce_point(&r);
      input.extend_from_slice(message);
      if let Some(c) = Self::challenge_hash(&input) {
        let k_hat = k_tilde + sk * c;
        return Ok(serialize(&[Ser::Scalar(k_hat), Ser::Scalar(c)]));
      }
    }
    Err(Error::SignerFailed("Schnorr nonce retry limit exceeded".into()))
  }

  fn verify(&self, hk: &G1Projective, pk: &G1Projective, sig: &[u8], message: &[u8]) -> Result<()> {
    let (s, c) = Self::parse(sig)?;
    // R = s*H0 - c*pk
    let r = hk * s - pk * c;
    let mut input = Self::serialize_nonce_point(&r);
    input.extend_from_slice(message);
    if Self::challenge_hash_reduced(&input) == c {
      Ok(())
    } else {
      Err(Error::VerificationFailed("key binding signature"))
    }
  }

  fn adapt_sig(&self, sig: &[u8], r_key: &Scalar, _message: &[u8]) -> Result<Vec<u8>> {
    let (s, c) = Self::parse(sig)?;
    Ok(serialize(&[Ser::Scalar(s + c * r_key), Ser::Scalar(c)]))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use bls12_381_plus::G1Projective;

  fn seeded() -> ScalarSource {
    ScalarSource::Seeded {
      seed: b"keybind-test-seed".to_vec(),
      dst: b"keybind-test-dst".to_vec(),
    }
  }

  #[test]
  fn sign_verify_roundtrip_on_base_point() {
    let scheme = SchnorrBls12381;
    let hk = G1Projective::GENERATOR;
    let (sk, pk) = scheme.key_gen(&hk, &seeded()).unwrap();
    let msg = b"a 32-byte-ish message to sign...";
    let sig = scheme.sign(&hk, &sk, msg, &seeded()).unwrap();
    assert_eq!(sig.len(), scheme.signature_length());
    scheme.verify(&hk, &pk, &sig, msg).unwrap();
  }

  /// Every message must be signable, not just a lucky majority.
  ///
  /// `sign` rejects a nonce whose challenge hash lands >= r, which happens
  /// for about 55% of attempts - r is roughly 0.453 * 2^256, not the
  /// vanishing probability the retry loop was once commented as. A seeded
  /// scalar source re-draws the *same* nonce every time, so before
  /// `ScalarSource::for_attempt` existed this failed outright for slightly
  /// over half of these messages. One message would not have caught it.
  #[test]
  fn every_message_is_signable_from_a_deterministic_source() {
    let scheme = SchnorrBls12381;
    let hk = G1Projective::GENERATOR;
    let (sk, pk) = scheme.key_gen(&hk, &seeded()).unwrap();
    for i in 0..64u32 {
      let msg = format!("message {i}");
      let sig = scheme
        .sign(&hk, &sk, msg.as_bytes(), &seeded())
        .unwrap_or_else(|e| panic!("message {i} could not be signed: {e}"));
      scheme
        .verify(&hk, &pk, &sig, msg.as_bytes())
        .unwrap_or_else(|e| panic!("message {i} did not verify: {e}"));
    }
  }

  /// Retrying against a seeded source must actually change the nonce.
  #[test]
  fn a_seeded_source_yields_a_different_scalar_on_each_attempt() {
    let source = seeded();
    let draws: Vec<_> = (0..4).map(|i| source.for_attempt(i).calculate(1).unwrap()[0]).collect();
    assert_eq!(draws[0], source.calculate(1).unwrap()[0], "attempt 0 must leave existing vectors alone");
    for i in 1..draws.len() {
      assert_ne!(draws[i], draws[0], "attempt {i} redrew the same scalar");
    }
  }

  #[test]
  fn verify_rejects_wrong_message_and_key() {
    let scheme = SchnorrBls12381;
    let hk = G1Projective::GENERATOR;
    let (sk, pk) = scheme.key_gen(&hk, &seeded()).unwrap();
    let sig = scheme.sign(&hk, &sk, b"message one", &seeded()).unwrap();
    assert!(scheme.verify(&hk, &pk, &sig, b"message two").is_err());
    assert!(scheme.verify(&hk, &(pk + hk), &sig, b"message one").is_err());
  }

  /// The unlinkability mechanism: an adapted signature must verify against
  /// the correspondingly blinded public key, and only that one.
  #[test]
  fn adapt_sig_verifies_under_randomized_key() {
    let scheme = SchnorrBls12381;
    let hk = G1Projective::GENERATOR;
    let (sk, pk) = scheme.key_gen(&hk, &seeded()).unwrap();
    let msg = b"bound to this presentation";
    let sig = scheme.sign(&hk, &sk, msg, &seeded()).unwrap();

    let r_key = ScalarSource::Seeded {
      seed: b"randomizer".to_vec(),
      dst: b"randomizer-dst".to_vec(),
    }
    .calculate(1)
    .unwrap()[0];

    let adapted = scheme.adapt_sig(&sig, &r_key, msg).unwrap();
    let pk_tilde = pk + hk * r_key;
    scheme.verify(&hk, &pk_tilde, &adapted, msg).unwrap();
    // The adapted signature must NOT verify under the original key.
    assert!(scheme.verify(&hk, &pk, &adapted, msg).is_err());
  }

  #[test]
  fn sec1_nonce_encoding_is_97_octets_with_tag() {
    let encoded = SchnorrBls12381::serialize_nonce_point(&G1Projective::GENERATOR);
    assert_eq!(encoded.len(), 97, "SEC1 uncompressed: tag + x + y");
    assert_eq!(encoded[0], 0x04);
  }

  #[test]
  fn parse_rejects_malformed_signatures() {
    assert!(SchnorrBls12381::parse(&[0u8; 63]).is_err());
    assert!(SchnorrBls12381::parse(&[0xffu8; 64]).is_err(), "non-canonical scalars");
  }
}
