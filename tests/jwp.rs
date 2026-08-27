// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Tests for the credential container ([`zk_cred_bbs::jwp`]).
//!
//! Two kinds of test here, deliberately separated:
//!
//! - **Known answers** for base64url, which is hand-implemented in this
//!   crate. A self-consistent encode/decode round trip would pass with a
//!   completely wrong alphabet, so the table below comes from RFC 4648 §10
//!   and from an independent implementation, not from this one.
//! - **Round trips and rejections** for everything above that, where the
//!   property being checked really is "what went in comes out", and where
//!   the interesting cases are the malformed ones.
//!
//! The end-to-end test at the bottom is the one that matters most: it runs
//! a real credential through issue, present and verify in container form,
//! so a container that encodes cleanly but describes the wrong message
//! vector still fails.

use serde_json::{Map, Value, json};
use zk_cred_bbs::blind::{BlindSuite, Disclosure, SCHNORR_SUITE_ID};
use zk_cred_bbs::jwp::{self, ALG, IssuedJwp, IssuerHeaderView, KB_SCHNORR, PresentedJwp};
use zk_cred_bbs::keybind::SchnorrBls12381;
use zk_cred_bbs::suite::{ScalarSource, Suite};

/// RFC 4648 §10's own vectors, unpadded, plus cases that exercise the two
/// characters base64url differs from base64 in (`-` and `_`) and the
/// 1-, 2- and 3-byte tail lengths. Cross-checked against Python's
/// `base64.urlsafe_b64encode`.
const B64_KNOWN_ANSWERS: &[(&[u8], &str)] = &[
  (&[], ""),
  (&[102], "Zg"),
  (&[102, 111], "Zm8"),
  (&[102, 111, 111], "Zm9v"),
  (&[102, 111, 111, 98], "Zm9vYg"),
  (&[102, 111, 111, 98, 97], "Zm9vYmE"),
  (&[102, 111, 111, 98, 97, 114], "Zm9vYmFy"),
  (&[251, 255, 254], "-__-"),
  (&[255, 255, 255, 255, 255], "______8"),
  (&[0, 1, 2, 3, 4, 5, 6, 7], "AAECAwQFBgc"),
  (&[0], "AA"),
  (&[208, 13], "0A0"),
  (&[250, 251, 252, 253, 254, 255], "-vv8_f7_"),
];

/// The base64url here is hand-written, so it gets known answers rather
/// than a round trip. `Zg` vs `Zg==` is the whole point: JWP compact
/// serialization is unpadded, and a padded encoder produces a `.`-and-`~`
/// delimited string that other implementations cannot split.
#[test]
fn base64url_matches_known_answers() {
  for (input, expected) in B64_KNOWN_ANSWERS {
    // Reached through the container, since the codec itself is private.
    // One payload, because a zero-length payload GROUP and a single
    // omitted payload both encode to the empty string - an ambiguity the
    // header's own "at least one claim" rule keeps unreachable.
    let jwp = IssuedJwp {
      issuer_header: input.to_vec(),
      payloads: vec![b"p".to_vec()],
      signature: vec![1],
    };
    let encoded = jwp.encode();
    let got = encoded.split('.').next().unwrap();
    assert_eq!(got, *expected, "encoding {input:?}");

    let decoded = IssuedJwp::decode(&encoded).expect("decodes");
    assert_eq!(decoded.issuer_header, *input, "round trip for {input:?}");
  }
}

#[test]
fn base64url_rejects_malformed_input() {
  // A 4k+1-character group cannot be the encoding of any octet string.
  assert!(IssuedJwp::decode("Zg9vYmFyZ").is_err(), "impossible length");
  // Characters outside the URL-safe alphabet, including base64's own.
  for bad in ["Zm9+Yg.QQ.QQ", "Zm9/Yg.QQ.QQ", "Zm9vYg==.QQ.QQ", "Zm9 vYg.QQ.QQ"] {
    assert!(IssuedJwp::decode(bad).is_err(), "should reject {bad:?}");
  }
}

// ---------------------------------------------------------------------------
// Compact serialization shape
// ---------------------------------------------------------------------------

#[test]
fn issued_and_presented_forms_have_the_right_part_counts() {
  let issued = IssuedJwp {
    issuer_header: b"{}".to_vec(),
    payloads: vec![b"a".to_vec(), b"b".to_vec()],
    signature: vec![9; 4],
  };
  assert_eq!(issued.encode().split('.').count(), 3, "issued form is 3 parts");

  let presented = PresentedJwp {
    presentation_header: b"{}".to_vec(),
    issuer_header: b"{}".to_vec(),
    payloads: vec![Some(b"a".to_vec()), None],
    proof: vec![9; 4],
  };
  assert_eq!(presented.encode().split('.').count(), 4, "presented form is 4 parts");

  assert!(IssuedJwp::decode("a.b").is_err());
  assert!(IssuedJwp::decode("a.b.c.d").is_err());
  assert!(PresentedJwp::decode("a.b.c").is_err());
}

/// The presentation header is the FIRST part, not the second.
///
/// Both drafts this profile follows say so explicitly, and getting it
/// backwards is invisible locally - our own decoder would read back
/// whatever our encoder wrote. It only shows up against another
/// implementation, as a header that will not parse.
#[test]
fn presented_form_puts_the_presentation_header_first() {
  let presented = PresentedJwp {
    presentation_header: br#"{"alg":"BBS-MOD","nonce":"n","aud":"a"}"#.to_vec(),
    issuer_header: br#"{"alg":"BBS-MOD","vct":"v"}"#.to_vec(),
    payloads: vec![Some(b"x".to_vec())],
    proof: vec![7],
  };
  let encoded = presented.encode();
  let first = encoded.split('.').next().unwrap();
  let decoded_first = IssuedJwp::decode(&format!("{first}.QQ.QQ")).unwrap().issuer_header;
  let text = String::from_utf8(decoded_first).unwrap();
  assert!(text.contains("nonce"), "first part must be the presentation header, got {text}");
}

/// Undisclosed payloads leave their slot empty, so positions are preserved
/// and consecutive `~` appear. Without this the verifier cannot tell which
/// message a disclosed payload belongs to.
#[test]
fn omitted_payloads_keep_their_positions() {
  let presented = PresentedJwp {
    presentation_header: b"{}".to_vec(),
    issuer_header: b"{}".to_vec(),
    payloads: vec![None, Some(b"foo".to_vec()), None, None, Some(b"bar".to_vec())],
    proof: vec![1],
  };
  let encoded = presented.encode();
  let payload_part = encoded.split('.').nth(2).unwrap();
  assert_eq!(payload_part, "~Zm9v~~~YmFy");

  let decoded = PresentedJwp::decode(&encoded).unwrap();
  assert_eq!(decoded.payloads, presented.payloads);
  assert_eq!(
    decoded.disclosures(),
    vec![Disclosure::Hide, Disclosure::Disclose, Disclosure::Hide, Disclosure::Hide, Disclosure::Disclose]
  );
  assert_eq!(decoded.disclosed_messages(), vec![b"foo".to_vec(), b"bar".to_vec()]);
}

/// A present-but-empty payload is `_`, an omitted one is nothing at all.
///
/// If both encoded to the empty string, disclosing a claim whose value
/// happens to encode to zero octets would be indistinguishable from
/// withholding it.
#[test]
fn an_empty_payload_is_distinct_from_an_omitted_one() {
  let presented = PresentedJwp {
    presentation_header: b"{}".to_vec(),
    issuer_header: b"{}".to_vec(),
    payloads: vec![Some(Vec::new()), None],
    proof: vec![1],
  };
  let encoded = presented.encode();
  assert_eq!(encoded.split('.').nth(2).unwrap(), "_~");
  let decoded = PresentedJwp::decode(&encoded).unwrap();
  assert_eq!(decoded.payloads, vec![Some(Vec::new()), None]);
  assert_eq!(decoded.disclosures(), vec![Disclosure::Disclose, Disclosure::Hide]);
}

#[test]
fn an_issued_form_may_not_omit_a_payload() {
  // Same shape as a presented form's withheld slot, which is exactly the
  // confusion worth rejecting: an issued credential discloses everything.
  assert!(IssuedJwp::decode("e30.~Zm9v.QQ").is_err());
}

// ---------------------------------------------------------------------------
// Header handling
// ---------------------------------------------------------------------------

fn header_with(cmap: Value, hcmap: Option<Value>) -> Vec<u8> {
  jwp::build_issuer_header("https://example.test/vct", cmap, hcmap, Some(KB_SCHNORR), &Map::new()).unwrap()
}

/// The signature covers the header's exact octets, so the container must
/// hand back what it was given - never a re-serialization.
#[test]
fn issuer_header_octets_survive_a_round_trip_verbatim() {
  // Deliberately not the key order this crate would emit, and with
  // whitespace, so a re-serializing implementation cannot accidentally
  // pass.
  let odd = br#"{ "vct":"x", "alg":"BBS-MOD", "cmap":{"a":[0,false]} }"#.to_vec();
  let issued = IssuedJwp {
    issuer_header: odd.clone(),
    payloads: vec![b"m".to_vec()],
    signature: vec![3],
  };
  let decoded = IssuedJwp::decode(&issued.encode()).unwrap();
  assert_eq!(decoded.issuer_header, odd, "header octets must be byte-identical");
  // ... and it must still parse, so verbatim preservation is not achieved
  // by refusing to understand it.
  let view = decoded.header().unwrap();
  assert_eq!(view.vct, "x");
}

#[test]
fn header_parsing_accepts_a_well_formed_map() {
  let octets = header_with(
    json!({"given_name": [0, false], "address": {"city": [1, false]}}),
    Some(json!({"secret": [2, false]})),
  );
  let view = IssuerHeaderView::parse(&octets).unwrap();
  assert_eq!(view.num_messages(), 3);
  assert_eq!(view.num_signer_messages(), 2);
  assert_eq!(view.kb.as_deref(), Some(KB_SCHNORR));
  assert_eq!(view.pointers(), vec!["/given_name", "/address/city", "/secret"]);
  assert_eq!(view.index_of("/address/city"), Some(1));
  assert_eq!(view.index_of("/nope"), None);
}

/// Every rejection below is a case where accepting the header would
/// produce a proof over a message vector that does not mean what the map
/// says it means - all of which surface downstream as an unhelpful length
/// error or a proof that simply will not verify.
#[test]
fn header_parsing_rejects_maps_that_would_mislead() {
  let cases: &[(&str, Vec<u8>)] = &[
    ("index gap", header_with(json!({"a": [0, false], "b": [2, false]}), None)),
    ("duplicate index", header_with(json!({"a": [0, false], "b": [0, false]}), None)),
    (
      "issuer claim above the signer/holder split",
      header_with(json!({"a": [0, false], "b": [2, false]}), Some(json!({"c": [1, false]}))),
    ),
    ("scalar encoding", header_with(json!({"a": [0, true]}), None)),
    ("empty map", header_with(json!({}), None)),
    ("leaf is not an annotation", header_with(json!({"a": "nope"}), None)),
    ("index over the limit", header_with(json!({"a": [9999, false]}), None)),
  ];
  for (name, octets) in cases {
    assert!(IssuerHeaderView::parse(octets).is_err(), "should reject: {name}");
  }

  // Wrong or missing algorithm, and an unrecognised key binding scheme.
  for (name, raw) in [
    ("no alg", r#"{"vct":"v","cmap":{"a":[0,false]}}"#),
    ("wrong alg", r#"{"alg":"BBS","vct":"v","cmap":{"a":[0,false]}}"#),
    ("no vct", r#"{"alg":"BBS-MOD","cmap":{"a":[0,false]}}"#),
    ("no cmap", r#"{"alg":"BBS-MOD","vct":"v"}"#),
    ("foreign kb", r#"{"alg":"BBS-MOD","vct":"v","kb":"ecdsa-p256-db","cmap":{"a":[0,false]}}"#),
    ("not an object", r#"["alg"]"#),
    ("not JSON", "{"),
  ] {
    assert!(IssuerHeaderView::parse(raw.as_bytes()).is_err(), "should reject: {name}");
  }
}

/// `ecdsa-p256-db` is the draft's own device binding, and it reserves four
/// message slots this profile does not reserve. Silently treating it as
/// ours would read every claim index four positions off.
#[test]
fn the_drafts_own_key_binding_is_refused_by_name() {
  let raw = format!(r#"{{"alg":"{ALG}","vct":"v","kb":"ecdsa-p256-db","cmap":{{"a":[0,false]}}}}"#);
  let err = IssuerHeaderView::parse(raw.as_bytes()).unwrap_err().to_string();
  assert!(err.contains("ecdsa-p256-db"), "the error should name the scheme it refused: {err}");
}

#[test]
fn a_presentation_header_needs_nonce_and_aud() {
  let issuer = header_with(json!({"a": [0, false]}), None);
  let make = |ph: Vec<u8>| PresentedJwp {
    presentation_header: ph,
    issuer_header: issuer.clone(),
    payloads: vec![Some(b"m".to_vec())],
    proof: vec![1],
  };
  assert!(make(jwp::build_presentation_header("n", "a", &Map::new()).unwrap()).header().is_ok());
  for bad in [
    r#"{"alg":"BBS-MOD","aud":"a"}"#,
    r#"{"alg":"BBS-MOD","nonce":"n"}"#,
    r#"{"nonce":"n","aud":"a"}"#,
    r#"{"alg":"BBS","nonce":"n","aud":"a"}"#,
  ] {
    assert!(make(bad.as_bytes().to_vec()).header().is_err(), "should reject {bad}");
  }
}

/// A caller's extra header parameters must not be able to restate the
/// ones built from validated inputs.
#[test]
fn extra_header_parameters_cannot_overwrite_reserved_ones() {
  for reserved in ["alg", "vct", "kb", "cmap", "hcmap"] {
    let mut extra = Map::new();
    extra.insert(reserved.to_string(), json!("smuggled"));
    assert!(
      jwp::build_issuer_header("v", json!({"a": [0, false]}), None, None, &extra).is_err(),
      "should reject extra {reserved:?}"
    );
  }
  let mut extra = Map::new();
  extra.insert("iss".into(), json!("https://issuer.test"));
  let octets = jwp::build_issuer_header("v", json!({"a": [0, false]}), None, None, &extra).unwrap();
  assert!(
    String::from_utf8(octets).unwrap().contains("https://issuer.test"),
    "non-reserved extras are carried"
  );
}

#[test]
fn a_payload_count_that_disagrees_with_the_map_is_rejected() {
  let octets = header_with(json!({"a": [0, false], "b": [1, false]}), None);
  let issued = IssuedJwp {
    issuer_header: octets.clone(),
    payloads: vec![b"only one".to_vec()],
    signature: vec![1],
  };
  assert!(issued.header().is_err(), "2 mapped claims but 1 payload");

  let presented = PresentedJwp {
    presentation_header: jwp::build_presentation_header("n", "a", &Map::new()).unwrap(),
    issuer_header: octets,
    payloads: vec![Some(b"a".to_vec())],
    proof: vec![1],
  };
  assert!(presented.header().is_err(), "2 mapped messages but 1 payload slot");
}

// ---------------------------------------------------------------------------
// Claim mapping
// ---------------------------------------------------------------------------

#[test]
fn cmap_assigns_indices_deterministically() {
  let claims = json!({"z": 1, "a": 2, "m": {"b": 3, "a": 4}});
  let (cmap_a, messages_a, pointers_a) = jwp::build_cmap(&claims, 0).unwrap();
  // Same claims written in a different key order must map identically -
  // otherwise the issuer and the holder can derive different vectors from
  // the same document.
  let reordered = json!({"m": {"a": 4, "b": 3}, "a": 2, "z": 1});
  let (cmap_b, messages_b, pointers_b) = jwp::build_cmap(&reordered, 0).unwrap();

  assert_eq!(pointers_a, vec!["/a", "/m/a", "/m/b", "/z"], "sorted by pointer");
  assert_eq!(pointers_a, pointers_b);
  assert_eq!(messages_a, messages_b);
  assert_eq!(cmap_a, cmap_b);
  assert_eq!(messages_a[0], b"2".to_vec(), "the message is the claim's JSON value");
}

#[test]
fn cmap_offsets_holder_claims_past_the_issuer_ones() {
  let (issuer_cmap, issuer_messages, _) = jwp::build_cmap(&json!({"a": 1, "b": 2}), 0).unwrap();
  let (holder_cmap, holder_messages, _) = jwp::build_cmap(&json!({"secret": 3}), issuer_messages.len()).unwrap();
  let view = IssuerHeaderView::parse(&header_with(issuer_cmap, Some(holder_cmap))).unwrap();
  assert_eq!(view.num_signer_messages(), 2);
  assert_eq!(view.index_of("/secret"), Some(2));
  assert_eq!(holder_messages.len(), 1);
}

/// Empty containers are leaves in their own right. Dropping them would
/// make `{"a":{}}` and `{"a":{"b":1}}`-minus-`b` collide, and more
/// importantly would let a claim vanish from the map without changing it.
#[test]
fn empty_containers_are_leaves() {
  let (_, messages, pointers) = jwp::build_cmap(&json!({"a": {}, "b": [], "c": 1}), 0).unwrap();
  assert_eq!(pointers, vec!["/a", "/b", "/c"]);
  assert_eq!(messages[0], b"{}".to_vec());
  assert_eq!(messages[1], b"[]".to_vec());
}

/// Without RFC 6901 escaping, a claim named `a/b` and a nested `a.b` would
/// produce the same pointer, so disclosing one would disclose the other.
#[test]
fn claim_names_containing_pointer_syntax_stay_distinct() {
  let (_, _, flat) = jwp::build_cmap(&json!({"a/b": 1}), 0).unwrap();
  let (_, _, nested) = jwp::build_cmap(&json!({"a": {"b": 1}}), 0).unwrap();
  assert_eq!(flat, vec!["/a~1b"]);
  assert_eq!(nested, vec!["/a/b"]);
  assert_ne!(flat, nested);

  let (_, _, tilde) = jwp::build_cmap(&json!({"a~b": 1}), 0).unwrap();
  assert_eq!(tilde, vec!["/a~0b"]);
}

#[test]
fn cmap_rejects_documents_it_cannot_map() {
  assert!(jwp::build_cmap(&json!({}), 0).is_err(), "nothing to sign");
  assert!(jwp::build_cmap(&json!([1, 2]), 0).is_err(), "not an object");
  assert!(jwp::build_cmap(&json!("scalar"), 0).is_err(), "not an object");
}

#[test]
fn arrays_are_mapped_element_by_element() {
  let (_, messages, pointers) = jwp::build_cmap(&json!({"nationalities": ["SE", "JP"]}), 0).unwrap();
  assert_eq!(pointers, vec!["/nationalities/0", "/nationalities/1"]);
  assert_eq!(messages, vec![b"\"SE\"".to_vec(), b"\"JP\"".to_vec()]);
}

#[test]
fn disclosures_map_requested_claims_onto_message_indices() {
  let view = IssuerHeaderView::parse(&header_with(json!({"a": [0, false], "b": [1, false]}), Some(json!({"s": [2, false]})))).unwrap();
  assert_eq!(
    jwp::disclosures_for(&view, &["/b".to_string(), "/s".to_string()]).unwrap(),
    vec![Disclosure::Hide, Disclosure::Disclose, Disclosure::Disclose]
  );
  assert_eq!(jwp::disclosures_for(&view, &[]).unwrap(), vec![Disclosure::Hide; 3]);

  // A verifier asking for a claim the credential does not have is told so,
  // rather than handed a proof that quietly lacks it.
  assert!(jwp::disclosures_for(&view, &["/missing".to_string()]).is_err());
}

// ---------------------------------------------------------------------------
// End to end
// ---------------------------------------------------------------------------

/// A whole credential through the container: issue, present, verify.
///
/// The point of running this in container form rather than over raw
/// message lists is that the container decides the message vector. A cmap
/// that is internally consistent but disagrees with what was signed still
/// encodes and decodes perfectly, and only fails here.
#[test]
fn a_credential_round_trips_through_the_container() {
  let suite = BlindSuite::new(
    Suite::new(ScalarSource::Seeded {
      seed: b"jwp-round-trip-seed".to_vec(),
      dst: b"JWP_TEST_DST_".to_vec(),
    }),
    SchnorrBls12381,
    SCHNORR_SUITE_ID,
  );

  // --- Holder: commit to the claims the issuer will not see.
  let holder_claims = json!({"device_secret": "s3cret"});
  let (hcmap, committed_messages, _) = jwp::build_cmap(&holder_claims, 1).unwrap();

  // A software key binding key stands in for the authenticator here; the
  // hardware-signature path is covered by tests/vectors.rs.
  let (keybind_sk, keybind_pk) = test_keybind_key(7);
  let (commit_state, secret_prover_blind, commit_challenge) = suite.commit_init(&committed_messages, std::slice::from_ref(&keybind_pk)).unwrap();
  let commitment = suite
    .commit_finalize(&commit_state, &[schnorr_sign(&keybind_sk, &challenge_octets(commit_challenge), "commit")])
    .unwrap();

  // --- Issuer: map its own claims, build the header, blind-sign.
  let issuer_claims = json!({"given_name": "Alice"});
  let (cmap, issuer_messages, _) = jwp::build_cmap(&issuer_claims, 0).unwrap();
  assert_eq!(issuer_messages.len(), 1, "the hcmap offset above assumes this");

  let mut extra = Map::new();
  extra.insert("iss".into(), json!("https://issuer.test"));
  let issuer_header = jwp::build_issuer_header("https://example.test/id-card", cmap, Some(hcmap), Some(KB_SCHNORR), &extra).unwrap();

  let (sk, pk) = test_issuer_key();
  let signature = suite.blind_sign(&sk, &pk, &commitment, &issuer_header, &issuer_messages).unwrap();

  let issued = IssuedJwp {
    issuer_header: issuer_header.clone(),
    payloads: issuer_messages.clone(),
    signature,
  };
  let compact = issued.encode();

  // --- Holder: read it back off the wire and check it before storing.
  let stored = IssuedJwp::decode(&compact).unwrap();
  let view = stored.header().unwrap();
  assert_eq!(view.vct, "https://example.test/id-card");
  assert_eq!(view.num_messages(), 2);
  assert_eq!(view.pointers(), vec!["/given_name", "/device_secret"]);

  let mut all_messages = stored.payloads.clone();
  all_messages.extend(committed_messages.iter().cloned());
  suite
    .verify_blind_sign(
      &pk,
      &stored.signature,
      &stored.issuer_header,
      &all_messages,
      view.num_signer_messages(),
      std::slice::from_ref(&keybind_pk),
      &secret_prover_blind,
    )
    .expect("the issued credential must validate before it is stored");

  // --- Holder: present, disclosing only the name.
  let presentation_header = jwp::build_presentation_header("nonce-from-the-verifier", "https://verifier.test", &Map::new()).unwrap();
  let disclosures = jwp::disclosures_for(&view, &["/given_name".to_string()]).unwrap();
  assert_eq!(disclosures, vec![Disclosure::Disclose, Disclosure::Hide]);

  let (proof_state, _info, challenges) = suite
    .blind_proof_gen_init(
      &pk,
      &stored.signature,
      &stored.issuer_header,
      &presentation_header,
      &all_messages,
      view.num_signer_messages(),
      &disclosures,
      std::slice::from_ref(&keybind_pk),
      &secret_prover_blind,
    )
    .unwrap();
  let proof_sigs: Vec<Vec<u8>> = challenges.iter().map(|c| schnorr_sign(&keybind_sk, c, "proof")).collect();
  let proof = suite.blind_proof_gen_finalize(&proof_state, &proof_sigs).unwrap();

  let presented = PresentedJwp {
    presentation_header,
    issuer_header: stored.issuer_header.clone(),
    payloads: all_messages
      .iter()
      .zip(&disclosures)
      .map(|(m, d)| if *d == Disclosure::Disclose { Some(m.clone()) } else { None })
      .collect(),
    proof,
  };
  let presented_compact = presented.encode();

  // --- Verifier: nothing but the compact string.
  let received = PresentedJwp::decode(&presented_compact).unwrap();
  let view = received.header().unwrap();
  suite
    .blind_proof_verify(
      &pk,
      &received.proof,
      &received.issuer_header,
      &received.presentation_header,
      view.num_signer_messages(),
      &received.disclosed_messages(),
      &received.disclosures(),
    )
    .expect("the presentation must verify");

  assert_eq!(received.disclosed_messages(), vec![b"\"Alice\"".to_vec()], "only the name is revealed");
  assert_eq!(received.payloads[1], None, "the committed claim stays hidden");

  // The issuer header crossed two wire encodings unchanged - which is what
  // made the two BBS `header` inputs agree.
  assert_eq!(received.issuer_header, issuer_header);
}

/// A presentation whose disclosed payload has been swapped for another
/// value must not verify, even though the container is still well-formed.
#[test]
fn a_tampered_payload_fails_verification() {
  // Reuses the round trip above through its own construction rather than
  // sharing state, so this test still means something if that one changes.
  let suite = BlindSuite::new(
    Suite::new(ScalarSource::Seeded {
      seed: b"jwp-tamper-seed".to_vec(),
      dst: b"JWP_TEST_DST_".to_vec(),
    }),
    SchnorrBls12381,
    SCHNORR_SUITE_ID,
  );
  let (keybind_sk, keybind_pk) = test_keybind_key(11);
  let (sk, pk) = test_issuer_key();

  let (cmap, issuer_messages, _) = jwp::build_cmap(&json!({"given_name": "Alice", "age": 42}), 0).unwrap();
  let (hcmap, committed_messages, _) = jwp::build_cmap(&json!({"secret": "x"}), issuer_messages.len()).unwrap();
  let issuer_header = jwp::build_issuer_header("v", cmap, Some(hcmap), Some(KB_SCHNORR), &Map::new()).unwrap();

  let (commit_state, spb, challenge) = suite.commit_init(&committed_messages, std::slice::from_ref(&keybind_pk)).unwrap();
  let commitment = suite
    .commit_finalize(&commit_state, &[schnorr_sign(&keybind_sk, &challenge_octets(challenge), "commit")])
    .unwrap();
  let signature = suite.blind_sign(&sk, &pk, &commitment, &issuer_header, &issuer_messages).unwrap();

  let mut all_messages = issuer_messages.clone();
  all_messages.extend(committed_messages.iter().cloned());
  let view = IssuerHeaderView::parse(&issuer_header).unwrap();
  let disclosures = jwp::disclosures_for(&view, &["/given_name".to_string()]).unwrap();

  let ph = jwp::build_presentation_header("n", "a", &Map::new()).unwrap();
  let (state, _info, challenges) = suite
    .blind_proof_gen_init(
      &pk,
      &signature,
      &issuer_header,
      &ph,
      &all_messages,
      view.num_signer_messages(),
      &disclosures,
      &[keybind_pk],
      &spb,
    )
    .unwrap();
  let sigs: Vec<Vec<u8>> = challenges.iter().map(|c| schnorr_sign(&keybind_sk, c, "proof")).collect();
  let proof = suite.blind_proof_gen_finalize(&state, &sigs).unwrap();

  let mut presented = PresentedJwp {
    presentation_header: ph,
    issuer_header: issuer_header.clone(),
    payloads: all_messages
      .iter()
      .zip(&disclosures)
      .map(|(m, d)| if *d == Disclosure::Disclose { Some(m.clone()) } else { None })
      .collect(),
    proof,
  };
  // Well-formed container, different claimed value.
  presented.payloads[view.index_of("/given_name").unwrap()] = Some(b"\"Mallory\"".to_vec());

  let received = PresentedJwp::decode(&presented.encode()).unwrap();
  let view = received.header().expect("the container is still structurally valid");
  assert!(
    suite
      .blind_proof_verify(
        &pk,
        &received.proof,
        &received.issuer_header,
        &received.presentation_header,
        view.num_signer_messages(),
        &received.disclosed_messages(),
        &received.disclosures(),
      )
      .is_err(),
    "a swapped payload must not verify"
  );
}

// --- test key helpers -------------------------------------------------------
//
// A software stand-in for the authenticator, so this file can exercise the
// container end to end without a token. The hardware-signature path is
// covered by tests/vectors.rs against real captures; nothing here is a
// substitute for that.

use bls12_381_plus::{G1Projective, G2Projective, Scalar};
use zk_cred_bbs::bbs::{Ser, serialize};
use zk_cred_bbs::keybind::SignatureScheme;

/// The generator a single key binding key is defined over - DELTA 1: the
/// curve's own base point, because a hardware authenticator can only
/// scalar-multiply that one.
fn keybind_generator() -> G1Projective {
  G1Projective::GENERATOR
}

fn test_issuer_key() -> (Scalar, Vec<u8>) {
  let sk = Scalar::from(0x5150_u64);
  (sk, serialize(&[Ser::G2(G2Projective::GENERATOR * sk)]))
}

fn test_keybind_key(seed: u64) -> (Scalar, Vec<u8>) {
  let sk = Scalar::from(seed) + Scalar::from(1u64);
  (sk, serialize(&[Ser::G1(keybind_generator() * sk)]))
}

fn signer_scalars(tag: &str) -> ScalarSource {
  ScalarSource::Seeded {
    seed: format!("keybind-{tag}").into_bytes(),
    dst: b"KEYBIND_TEST_DST_".to_vec(),
  }
}

/// Signs exactly what the authenticator would: the 32 octets handed back
/// by `commit_init` / `blind_proof_gen_init`.
fn schnorr_sign(sk: &Scalar, message: &[u8], tag: &str) -> Vec<u8> {
  SchnorrBls12381
    .sign(&keybind_generator(), sk, message, &signer_scalars(tag))
    .expect("software keybind signature")
}

fn challenge_octets(c: Scalar) -> Vec<u8> {
  serialize(&[Ser::Scalar(c)])
}
