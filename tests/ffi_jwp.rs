// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Tests for the container's FFI surface, and the generator for the
//! fixture the native SDKs test against.
//!
//! These go through `ffi_api` rather than the Rust API on purpose. That
//! layer draws its randomness from the system - `ScalarSource::Seeded` is
//! deliberately unreachable from it - so nothing here can assert a byte
//! value. What it can assert is that a credential survives the whole
//! journey, which is the property that actually breaks when the mapping
//! between claims and messages is wrong.
//!
//! Run with `JWP_FIXTURE_OUT=<path>` to regenerate the SDK fixture.

#![cfg(feature = "uniffi")]

use serde_json::{Map, Value, json};
use zk_cred_bbs::bbs::{Ser, serialize};
use zk_cred_bbs::blind::{BlindSuite, PLAIN_SUITE_ID, SCHNORR_SUITE_ID};
use zk_cred_bbs::ffi_api::*;
use zk_cred_bbs::jwp;
use zk_cred_bbs::keybind::{NullScheme, SchnorrBls12381, SignatureScheme};
use zk_cred_bbs::suite::{ScalarSource, Suite};

use bls12_381_plus::{G1Projective, G2Projective, Scalar};

const VCT: &str = "https://example.test/id-card";

/// The claims every case in this file is built from.
///
/// A function rather than two literals so the fixture records exactly what
/// was signed; a hand-copied duplicate would drift the moment either
/// changed.
fn issuer_claims_json() -> Value {
  json!({
    "given_name": "Alice",
    "family_name": "Andersson",
    "birth_date": "1990-01-31",
    "address": {"country": "SE", "locality": "Stockholm"},
    "nationalities": ["SE", "JP"],
  })
}

fn holder_claims_json() -> Value {
  json!({"device_pin_hash": "0f1e2d3c"})
}

fn issuer_key() -> (Scalar, Vec<u8>) {
  let sk = Scalar::from(0x5150_u64);
  (sk, serialize(&[Ser::G2(G2Projective::GENERATOR * sk)]))
}

/// A credential, issued. Returned in the shape a wallet would store: the
/// container plus the holder-side secrets that are not in it.
struct Fixture {
  issued_jwp: String,
  commitment: Vec<u8>,
  issuer_pk: Vec<u8>,
  committed_messages: Vec<Vec<u8>>,
  keybind_public_keys: Vec<Vec<u8>>,
  keybind_secret: Option<Scalar>,
  secret_prover_blind: Vec<u8>,
}

/// Issues a credential with the Rust API, which is the only side that has
/// the issuer's secret key and the only side allowed a seeded scalar
/// source. Deterministic, so the fixture it produces is stable.
fn issue(with_keybind: bool, seed: &str) -> Fixture {
  let scalars = ScalarSource::Seeded {
    seed: seed.as_bytes().to_vec(),
    dst: b"JWP_FIXTURE_DST_".to_vec(),
  };
  let suite_id = if with_keybind { SCHNORR_SUITE_ID } else { PLAIN_SUITE_ID };

  let issuer_claims = issuer_claims_json();
  let holder_claims = holder_claims_json();

  let (cmap, issuer_messages, _) = jwp::build_cmap(&issuer_claims, 0).unwrap();
  let (hcmap, committed_messages, _) = jwp::build_cmap(&holder_claims, issuer_messages.len()).unwrap();

  let mut extra = Map::new();
  extra.insert("iss".into(), json!("https://issuer.test"));
  let issuer_header = jwp::build_issuer_header(VCT, cmap, Some(hcmap), if with_keybind { Some(jwp::KB_SCHNORR) } else { None }, &extra).unwrap();

  let (sk, pk) = issuer_key();

  // Two suites, one shape. The generic parameter is the key binding
  // scheme, so the no-keybind case is the same code with `NullScheme`.
  macro_rules! run {
    ($scheme:expr) => {{
      let suite = BlindSuite::new(Suite::new(scalars.clone()), $scheme, suite_id);
      let (keybind_secret, keybind_public_keys) = if with_keybind {
        let ksk = Scalar::from(0x1234_u64);
        (Some(ksk), vec![serialize(&[Ser::G1(G1Projective::GENERATOR * ksk)])])
      } else {
        (None, vec![])
      };
      let (state, spb, challenge) = suite.commit_init(&committed_messages, &keybind_public_keys).unwrap();
      let sigs: Vec<Vec<u8>> = match keybind_secret {
        None => vec![],
        Some(ksk) => vec![
          $scheme
            .sign(&G1Projective::GENERATOR, &ksk, &serialize(&[Ser::Scalar(challenge)]), &scalars)
            .unwrap(),
        ],
      };
      let commitment = suite.commit_finalize(&state, &sigs).unwrap();
      let signature = suite.blind_sign(&sk, &pk, &commitment, &issuer_header, &issuer_messages).unwrap();
      (keybind_secret, keybind_public_keys, spb, signature, commitment)
    }};
  }

  let (keybind_secret, keybind_public_keys, spb, signature, commitment) = if with_keybind { run!(SchnorrBls12381) } else { run!(NullScheme) };

  let issued = jwp::IssuedJwp {
    issuer_header,
    payloads: issuer_messages,
    signature,
  };
  Fixture {
    issued_jwp: issued.encode(),
    commitment,
    issuer_pk: pk,
    committed_messages,
    keybind_public_keys,
    keybind_secret,
    secret_prover_blind: serialize(&[Ser::Scalar(spb)]),
  }
}

#[test]
fn inspect_reads_a_credential_without_verifying_it() {
  let f = issue(true, "inspect");
  let info = jwp_inspect(f.issued_jwp.clone()).unwrap();
  assert_eq!(info.vct, VCT);
  assert_eq!(info.kb.as_deref(), Some(jwp::KB_SCHNORR));
  assert_eq!(info.num_signer_messages, 7, "5 claims, one nested pair, one 2-element array");
  assert_eq!(
    info.pointers,
    vec![
      "/address/country",
      "/address/locality",
      "/birth_date",
      "/family_name",
      "/given_name",
      "/nationalities/0",
      "/nationalities/1",
      "/device_pin_hash",
    ]
  );
  assert_eq!(info.pointers.len(), info.num_signer_messages as usize + 1, "the holder's own claim is the tail");
}

#[test]
fn accept_validates_a_freshly_issued_credential() {
  let f = issue(true, "accept");
  let info = jwp_accept(
    BbsSuiteId::Schnorr,
    f.issued_jwp.clone(),
    f.issuer_pk.clone(),
    f.committed_messages.clone(),
    f.keybind_public_keys.clone(),
    f.secret_prover_blind.clone(),
  )
  .unwrap();
  assert_eq!(info.vct, VCT);
}

/// Each of these is a way the issuer, or someone between it and the
/// wallet, could hand over a credential that is not what was asked for.
#[test]
fn accept_rejects_a_credential_that_is_not_what_was_committed_to() {
  let f = issue(true, "accept-neg");

  let wrong_pk = {
    let (_, pk) = issuer_key();
    let mut other = pk.clone();
    other[0] ^= 0x01;
    other
  };
  assert!(
    jwp_accept(
      BbsSuiteId::Schnorr,
      f.issued_jwp.clone(),
      wrong_pk,
      f.committed_messages.clone(),
      f.keybind_public_keys.clone(),
      f.secret_prover_blind.clone()
    )
    .is_err(),
    "a different issuer key"
  );

  let mut other_messages = f.committed_messages.clone();
  other_messages[0] = b"\"something else\"".to_vec();
  assert!(
    jwp_accept(
      BbsSuiteId::Schnorr,
      f.issued_jwp.clone(),
      f.issuer_pk.clone(),
      other_messages,
      f.keybind_public_keys.clone(),
      f.secret_prover_blind.clone()
    )
    .is_err(),
    "different committed messages"
  );

  assert!(
    jwp_accept(
      BbsSuiteId::Schnorr,
      f.issued_jwp.clone(),
      f.issuer_pk.clone(),
      vec![],
      f.keybind_public_keys.clone(),
      f.secret_prover_blind.clone()
    )
    .is_err(),
    "a message count that disagrees with the header's map"
  );

  // Bound to a device key the wallet does not hold.
  let other_key = vec![serialize(&[Ser::G1(G1Projective::GENERATOR * Scalar::from(99u64))])];
  assert!(
    jwp_accept(
      BbsSuiteId::Schnorr,
      f.issued_jwp.clone(),
      f.issuer_pk.clone(),
      f.committed_messages.clone(),
      other_key,
      f.secret_prover_blind.clone()
    )
    .is_err(),
    "a different key binding key"
  );
}

/// The full journey with no authenticator in it.
///
/// The `Plain` suite has no key binding, so `present_init` returns no
/// challenges and the flow completes without anything to sign. That is
/// what lets the native SDKs run this same path on a device with no
/// token - see the fixture at the bottom.
#[test]
fn a_plain_credential_presents_and_verifies_through_the_ffi() {
  let f = issue(false, "plain-roundtrip");
  assert!(jwp_inspect(f.issued_jwp.clone()).unwrap().kb.is_none());

  jwp_accept(
    BbsSuiteId::Plain,
    f.issued_jwp.clone(),
    f.issuer_pk.clone(),
    f.committed_messages.clone(),
    vec![],
    f.secret_prover_blind.clone(),
  )
  .unwrap();

  let ph = jwp_build_presentation_header("nonce-1".into(), "https://verifier.test".into(), None).unwrap();
  let requested = vec!["/given_name".to_string(), "/address/country".to_string()];

  let init = jwp_present_init(
    BbsSuiteId::Plain,
    f.issued_jwp.clone(),
    f.issuer_pk.clone(),
    ph,
    requested.clone(),
    f.committed_messages.clone(),
    vec![],
    f.secret_prover_blind.clone(),
  )
  .unwrap();
  assert!(init.keybind_challenges.is_empty(), "no key binding, nothing to sign");

  let presented = jwp_present_finalize(BbsSuiteId::Plain, init.state, vec![]).unwrap();
  assert_eq!(presented.split('.').count(), 4);

  let result = jwp_verify(BbsSuiteId::Plain, presented, f.issuer_pk.clone()).unwrap();
  assert_eq!(result.vct, VCT);
  let got: Vec<(String, String)> = result.disclosed.into_iter().map(|d| (d.pointer, d.value_json)).collect();
  assert_eq!(
    got,
    vec![
      ("/address/country".to_string(), "\"SE\"".to_string()),
      ("/given_name".to_string(), "\"Alice\"".to_string()),
    ],
    "exactly the requested claims, in message order"
  );
}

/// Two presentations of the same credential must not be byte-identical.
///
/// This is the unlinkability property, and it is the one thing that would
/// break silently if the FFI ever drew its randomness from a fixed seed -
/// every presentation would still verify.
#[test]
fn presentations_are_unlinkable() {
  let f = issue(false, "unlinkable");
  let present = || {
    let ph = jwp_build_presentation_header("same-nonce".into(), "https://verifier.test".into(), None).unwrap();
    let init = jwp_present_init(
      BbsSuiteId::Plain,
      f.issued_jwp.clone(),
      f.issuer_pk.clone(),
      ph,
      vec!["/given_name".to_string()],
      f.committed_messages.clone(),
      vec![],
      f.secret_prover_blind.clone(),
    )
    .unwrap();
    jwp_present_finalize(BbsSuiteId::Plain, init.state, vec![]).unwrap()
  };
  let (a, b) = (present(), present());
  assert_ne!(a, b, "two presentations of one credential must differ");
  // ... and both must still verify, so the difference is re-randomisation
  // rather than damage.
  for p in [a, b] {
    jwp_verify(BbsSuiteId::Plain, p, f.issuer_pk.clone()).unwrap();
  }
}

#[test]
fn the_key_binding_path_presents_and_verifies() {
  let f = issue(true, "keybind-roundtrip");
  let ph = jwp_build_presentation_header("nonce-2".into(), "https://verifier.test".into(), None).unwrap();

  let init = jwp_present_init(
    BbsSuiteId::Schnorr,
    f.issued_jwp.clone(),
    f.issuer_pk.clone(),
    ph,
    vec!["/family_name".to_string()],
    f.committed_messages.clone(),
    f.keybind_public_keys.clone(),
    f.secret_prover_blind.clone(),
  )
  .unwrap();
  assert_eq!(init.keybind_challenges.len(), 1, "one challenge per key binding key");
  assert_eq!(init.keybind_challenges[0].len(), 32, "prehashed - DELTA 3");

  // Stands in for the authenticator.
  let ksk = f.keybind_secret.expect("this fixture is key bound");
  let sigs: Vec<Vec<u8>> = init
    .keybind_challenges
    .iter()
    .map(|c| SchnorrBls12381.sign(&G1Projective::GENERATOR, &ksk, c, &ScalarSource::System).unwrap())
    .collect();

  let presented = jwp_present_finalize(BbsSuiteId::Schnorr, init.state, sigs).unwrap();
  let result = jwp_verify(BbsSuiteId::Schnorr, presented, f.issuer_pk.clone()).unwrap();
  assert_eq!(result.disclosed.len(), 1);
  assert_eq!(result.disclosed[0].pointer, "/family_name");
  assert_eq!(result.disclosed[0].value_json, "\"Andersson\"");
}

#[test]
fn presenting_rejects_a_claim_the_credential_does_not_have() {
  let f = issue(false, "unknown-claim");
  let ph = jwp_build_presentation_header("n".into(), "a".into(), None).unwrap();
  assert!(
    jwp_present_init(
      BbsSuiteId::Plain,
      f.issued_jwp.clone(),
      f.issuer_pk.clone(),
      ph,
      vec!["/shoe_size".to_string()],
      f.committed_messages.clone(),
      vec![],
      f.secret_prover_blind.clone(),
    )
    .is_err()
  );
}

/// The carried state makes a round trip through storage the wallet
/// controls, so a damaged one must produce an error rather than a panic
/// across the FFI boundary - where a panic is an abort, not an exception.
#[test]
fn a_damaged_presentation_state_is_rejected_cleanly() {
  let f = issue(false, "damaged-state");
  let ph = jwp_build_presentation_header("n".into(), "a".into(), None).unwrap();
  let init = jwp_present_init(
    BbsSuiteId::Plain,
    f.issued_jwp.clone(),
    f.issuer_pk.clone(),
    ph,
    vec!["/given_name".to_string()],
    f.committed_messages.clone(),
    vec![],
    f.secret_prover_blind.clone(),
  )
  .unwrap();

  for cut in [0usize, 1, 7, init.state.len() / 2, init.state.len() - 1] {
    assert!(
      jwp_present_finalize(BbsSuiteId::Plain, init.state[..cut].to_vec(), vec![]).is_err(),
      "truncated to {cut} octets"
    );
  }
  let mut extended = init.state.clone();
  extended.push(0);
  assert!(jwp_present_finalize(BbsSuiteId::Plain, extended, vec![]).is_err(), "trailing content");

  let mut flipped = init.state.clone();
  let last = flipped.len() - 1;
  flipped[last] ^= 0xff;
  // Either it fails to parse or the proof fails - both are fine, an abort
  // is not.
  let _ = jwp_present_finalize(BbsSuiteId::Plain, flipped, vec![]);
}

#[test]
fn verify_rejects_a_presentation_that_was_tampered_with() {
  let f = issue(false, "verify-neg");
  let ph = jwp_build_presentation_header("n".into(), "https://verifier.test".into(), None).unwrap();
  let init = jwp_present_init(
    BbsSuiteId::Plain,
    f.issued_jwp.clone(),
    f.issuer_pk.clone(),
    ph,
    vec!["/given_name".to_string()],
    f.committed_messages.clone(),
    vec![],
    f.secret_prover_blind.clone(),
  )
  .unwrap();
  let presented = jwp_present_finalize(BbsSuiteId::Plain, init.state, vec![]).unwrap();

  let parts: Vec<&str> = presented.split('.').collect();
  // Swap the disclosed value for another one.
  let mut decoded = jwp::PresentedJwp::decode(&presented).unwrap();
  let index = decoded.payloads.iter().position(Option::is_some).unwrap();
  decoded.payloads[index] = Some(b"\"Mallory\"".to_vec());
  assert!(jwp_verify(BbsSuiteId::Plain, decoded.encode(), f.issuer_pk.clone()).is_err(), "swapped payload");

  // Present a claim that was withheld, without a proof covering it.
  let mut widened = jwp::PresentedJwp::decode(&presented).unwrap();
  let hidden = widened.payloads.iter().position(Option::is_none).unwrap();
  widened.payloads[hidden] = Some(b"\"SE\"".to_vec());
  assert!(
    jwp_verify(BbsSuiteId::Plain, widened.encode(), f.issuer_pk.clone()).is_err(),
    "widened disclosure"
  );

  // A different presentation header than the one that was proven over.
  let other_ph = jwp_build_presentation_header("a different nonce".into(), "https://verifier.test".into(), None).unwrap();
  let mut rebound = jwp::PresentedJwp::decode(&presented).unwrap();
  rebound.presentation_header = other_ph;
  assert!(
    jwp_verify(BbsSuiteId::Plain, rebound.encode(), f.issuer_pk.clone()).is_err(),
    "replayed against another session"
  );

  // Truncated container.
  assert!(jwp_verify(BbsSuiteId::Plain, parts[..3].join("."), f.issuer_pk.clone()).is_err(), "three parts");
}

#[test]
fn presentation_header_extras_are_carried_and_validated() {
  let ph = jwp_build_presentation_header("n".into(), "a".into(), Some(r#"{"sth":"abc"}"#.into())).unwrap();
  let text = String::from_utf8(ph).unwrap();
  assert!(text.contains("\"sth\":\"abc\""));

  assert!(jwp_build_presentation_header("n".into(), "a".into(), Some("not json".into())).is_err());
  assert!(jwp_build_presentation_header("n".into(), "a".into(), Some("[1,2]".into())).is_err());
  assert!(
    jwp_build_presentation_header("n".into(), "a".into(), Some(r#"{"aud":"elsewhere"}"#.into())).is_err(),
    "an extra must not restate a reserved parameter"
  );
}

// ---------------------------------------------------------------------------
// SDK fixture
// ---------------------------------------------------------------------------

/// Writes the fixture the native SDKs test against.
///
/// What this fixture proves, and what it does not: it is generated by the
/// implementation under test, so it says nothing about whether this crate
/// computes BBS correctly - `tests/vectors.rs` answers that, differentially
/// against Emil Lundberg's TypeScript. What the SDK tests need it for is
/// the layer above: that the packaging, the bindings and the container
/// survive the trip into Kotlin and Swift.
///
/// The `plain` case has no key binding, so an SDK can run the whole
/// present-and-verify path on a device with no authenticator attached.
#[test]
fn dump_sdk_fixture() {
  let Ok(path) = std::env::var("JWP_FIXTURE_OUT") else {
    return;
  };

  let mut cases = Map::new();
  for (name, with_keybind) in [("plain", false), ("keybind", true)] {
    let f = issue(with_keybind, name);
    let info = jwp_inspect(f.issued_jwp.clone()).unwrap();

    // A finished presentation, so a consumer that can only verify - the Go
    // relying party - has something real to verify. Only for the
    // no-keybind case: the other needs an authenticator signature, and a
    // software stand-in in a published fixture would invite someone to
    // treat it as a real one.
    let presented = if with_keybind {
      Value::Null
    } else {
      let ph = jwp_build_presentation_header("fixture-nonce".into(), "https://verifier.test".into(), None).unwrap();
      let init = jwp_present_init(
        BbsSuiteId::Plain,
        f.issued_jwp.clone(),
        f.issuer_pk.clone(),
        ph,
        vec!["/given_name".to_string(), "/address/country".to_string()],
        f.committed_messages.clone(),
        vec![],
        f.secret_prover_blind.clone(),
      )
      .unwrap();
      Value::String(jwp_present_finalize(BbsSuiteId::Plain, init.state, vec![]).unwrap())
    };

    cases.insert(
      name.to_string(),
      json!({
        "issued_jwp": f.issued_jwp,
        // The holder's commitment, so the issuer side can be exercised
        // from Go - which cannot commit, since no Go service ever holds a
        // credential.
        "commitment": hex::encode(&f.commitment),
        "issuer_claims": issuer_claims_json(),
        "holder_pointers": ["/device_pin_hash"],
        "presented_jwp": presented,
        "issuer_pk": hex::encode(&f.issuer_pk),
        // The issuer's own key, so the Go issuer path can be exercised
        // against exactly what Rust signed with. A fixed test value
        // (Scalar::from(0x5150)), not a credential.
        "issuer_sk": hex::encode(serialize(&[Ser::Scalar(issuer_key().0)])),
        "committed_messages": f.committed_messages.iter().map(hex::encode).collect::<Vec<_>>(),
        "keybind_public_keys": f.keybind_public_keys.iter().map(hex::encode).collect::<Vec<_>>(),
        "secret_prover_blind": hex::encode(&f.secret_prover_blind),
        "vct": info.vct,
        "pointers": info.pointers,
        "num_signer_messages": info.num_signer_messages,
      }),
    );
  }

  let doc = json!({
    "README": "Generated by `JWP_FIXTURE_OUT=<path> cargo test --features uniffi dump_sdk_fixture`. \
               Ground truth for the BBS algebra is test-vectors/emlun_reference.json, not this file; \
               this exists so the SDKs can exercise the container and the bindings.",
    "cases": Value::Object(cases),
  });
  std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).expect("write fixture");
  eprintln!("wrote {path}");
}
