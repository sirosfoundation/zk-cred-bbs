// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Rejection cases. A verifier that accepts everything passes every
//! positive test, so these carry as much weight as `vectors.rs`.

use serde_json::Value;
use std::str::FromStr;
use zk_cred_bbs::blind::{BlindSuite, Disclosure, SCHNORR_SUITE_ID};
use zk_cred_bbs::keybind::SchnorrBls12381;
use zk_cred_bbs::suite::{ScalarSource, Suite};

fn vectors() -> Value {
  serde_json::from_str(include_str!("../test-vectors/emlun_reference.json")).unwrap()
}

fn hex_of(v: &Value) -> Vec<u8> {
  hex::decode(v.as_str().unwrap()).unwrap()
}

fn hex_list(v: &Value) -> Vec<Vec<u8>> {
  v.as_array().unwrap().iter().map(hex_of).collect()
}

struct Fixture {
  suite: BlindSuite<SchnorrBls12381>,
  pk: Vec<u8>,
  header: Vec<u8>,
  ph: Vec<u8>,
  proof: Vec<u8>,
  issuer_known: usize,
  disclosed_messages: Vec<Vec<u8>>,
  disclosures: Vec<Disclosure>,
}

fn fixture() -> Fixture {
  let v = vectors();
  let hw = &v["hardware_keybind"];
  let suite = BlindSuite::new(
    Suite::new(ScalarSource::Seeded {
      seed: hex_of(&hw["mock_seed"]),
      dst: hex_of(&hw["mock_dst"]),
    }),
    SchnorrBls12381,
    SCHNORR_SUITE_ID,
  );
  let signer_messages = hex_list(&hw["signer_messages"]);
  let committed_messages = hex_list(&hw["committed_messages"]);
  let disclosures: Vec<Disclosure> = hw["disclosures"]
    .as_array()
    .unwrap()
    .iter()
    .map(|d| Disclosure::from_str(d.as_str().unwrap()).unwrap())
    .collect();
  let mut all = signer_messages.clone();
  all.extend(committed_messages.iter().cloned());
  let disclosed_messages: Vec<Vec<u8>> = all
    .iter()
    .zip(disclosures.iter())
    .filter(|(_, d)| **d == Disclosure::Disclose)
    .map(|(m, _)| m.clone())
    .collect();

  Fixture {
    suite,
    pk: hex_of(&hw["pk"]),
    header: hex_of(&hw["header"]),
    ph: hex_of(&hw["presentation_header"]),
    proof: hex_of(&hw["proof"]),
    issuer_known: signer_messages.len(),
    disclosed_messages,
    disclosures,
  }
}

impl Fixture {
  fn verify(&self, proof: &[u8], ph: &[u8], disclosed: &[Vec<u8>]) -> bool {
    self
      .suite
      .blind_proof_verify(&self.pk, proof, &self.header, ph, self.issuer_known, disclosed, &self.disclosures)
      .is_ok()
  }
}

#[test]
fn baseline_proof_verifies() {
  let f = fixture();
  assert!(f.verify(&f.proof, &f.ph, &f.disclosed_messages));
}

/// Binding to the presentation header is what stops a captured proof being
/// replayed into another session.
#[test]
fn rejects_wrong_presentation_header() {
  let f = fixture();
  let mut ph = f.ph.clone();
  ph[0] ^= 0x01;
  assert!(!f.verify(&f.proof, &ph, &f.disclosed_messages));
}

#[test]
fn rejects_altered_disclosed_message() {
  let f = fixture();
  let mut disclosed = f.disclosed_messages.clone();
  disclosed[0][0] ^= 0x01;
  assert!(!f.verify(&f.proof, &f.ph, &disclosed));
}

#[test]
fn rejects_wrong_issuer_public_key() {
  let f = fixture();
  let mut pk = f.pk.clone();
  pk[10] ^= 0x01;
  assert!(
    f.suite
      .blind_proof_verify(&pk, &f.proof, &f.header, &f.ph, f.issuer_known, &f.disclosed_messages, &f.disclosures,)
      .is_err()
  );
}

/// Every octet of the proof is covered by either the challenge or the
/// pairing check. Flipping a bit anywhere must be caught.
#[test]
fn rejects_bit_flips_throughout_the_proof() {
  let f = fixture();
  // Sample across the whole structure rather than testing every octet,
  // which would be slow: the length prefixes, the BBS proof body, the
  // commitments, the randomized keys, and the key binding signatures.
  let probes = [24, f.proof.len() / 4, f.proof.len() / 2, f.proof.len() * 3 / 4, f.proof.len() - 1];
  for &at in &probes {
    let mut bad = f.proof.clone();
    bad[at] ^= 0x01;
    assert!(!f.verify(&bad, &f.ph, &f.disclosed_messages), "a flipped bit at offset {at} was accepted");
  }
}

#[test]
fn rejects_truncated_and_extended_proofs() {
  let f = fixture();
  let mut short = f.proof.clone();
  short.truncate(f.proof.len() - 1);
  assert!(!f.verify(&short, &f.ph, &f.disclosed_messages));

  let mut long = f.proof.clone();
  long.push(0);
  assert!(!f.verify(&long, &f.ph, &f.disclosed_messages));

  assert!(!f.verify(&[], &f.ph, &f.disclosed_messages));
  assert!(!f.verify(&[0u8; 23], &f.ph, &f.disclosed_messages));
}

/// A holder must not be able to claim a message was disclosed when the
/// proof says otherwise, or shuffle which slot a disclosure refers to.
#[test]
fn rejects_mismatched_disclosure_pattern() {
  let f = fixture();
  let mut disclosures = f.disclosures.clone();
  // Turn a hidden message into a claimed disclosure.
  let hidden = disclosures.iter().position(|d| *d == Disclosure::Hide).expect("fixture has hidden messages");
  disclosures[hidden] = Disclosure::Disclose;
  assert!(
    f.suite
      .blind_proof_verify(&f.pk, &f.proof, &f.header, &f.ph, f.issuer_known, &f.disclosed_messages, &disclosures,)
      .is_err()
  );
}

/// The issuer-known split decides which generator each message is bound to;
/// lying about it must not verify.
#[test]
fn rejects_wrong_issuer_known_message_count() {
  let f = fixture();
  for wrong in [f.issuer_known - 1, f.issuer_known + 1] {
    assert!(
      f.suite
        .blind_proof_verify(&f.pk, &f.proof, &f.header, &f.ph, wrong, &f.disclosed_messages, &f.disclosures,)
        .is_err(),
      "issuer_known_messages_no = {wrong} was accepted"
    );
  }
}

/// A commitment whose device signature does not check out must be refused
/// by the issuer, not blind-signed anyway.
#[test]
fn issuer_rejects_commitment_with_bad_keybind_signature() {
  let v = vectors();
  let hw = &v["hardware_keybind"];
  let suite = BlindSuite::new(
    Suite::new(ScalarSource::Seeded {
      seed: hex_of(&hw["mock_seed"]),
      dst: hex_of(&hw["mock_dst"]),
    }),
    SchnorrBls12381,
    SCHNORR_SUITE_ID,
  );
  let sk = zk_cred_bbs::bbs::scalar_from_be(&hex_of(&hw["sk"])).unwrap();
  let pk = hex_of(&hw["pk"]);
  let header = hex_of(&hw["header"]);
  let signer_messages = hex_list(&hw["signer_messages"]);

  let good = hex_of(&hw["commitment_with_proof"]);
  assert!(suite.blind_sign(&sk, &pk, &good, &header, &signer_messages).is_ok());

  // Corrupt the trailing key binding signature.
  let mut bad = good.clone();
  let last = bad.len() - 1;
  bad[last] ^= 0x01;
  assert!(suite.blind_sign(&sk, &pk, &bad, &header, &signer_messages).is_err());

  // Corrupt the commitment point itself.
  let mut bad = good.clone();
  bad[20] ^= 0x01;
  assert!(suite.blind_sign(&sk, &pk, &bad, &header, &signer_messages).is_err());
}
