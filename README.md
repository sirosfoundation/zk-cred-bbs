# zk-cred-bbs

Blind BBS signatures with hardware key binding, in Rust.

> **Not reviewed, not for production.** This implements a construction that
> is explicitly pre-standardisation, against identifiers that are explicitly
> placeholders, and it has had no independent cryptographic review. Do not
> put it in front of a real relying party. See [`PROFILE.md`](PROFILE.md).

## What this is

A wallet credential can be selectively disclosed with BBS: the issuer signs a
list of messages once, and the holder later proves possession while revealing
only the messages they choose. This crate implements that, plus two things
plain BBS does not have:

- **Blind issuance** — the holder commits to some messages the issuer never
  sees, and the issuer signs the commitment.
- **Key binding** — the credential is bound to a key held by an
  authenticator, and each presentation carries a fresh signature from it,
  re-randomised so presentations stay unlinkable.

It also carries the credential container, so that the issuer, the wallet
and the verifier cannot disagree about which claim is which message - see
[the container](#the-container) below.

The construction is Emil Lundberg's; this is a Rust port of his TypeScript
implementation, which remains the normative reference. See
[`PROFILE.md`](PROFILE.md) for provenance, the four deliberate deviations
from the CFRG draft, and what the hardware test vector does and does not
prove.

## Status

| | |
|---|---|
| Base BBS (sign, verify, prove, verify) | implemented, matches reference |
| Blind issuance (commit, blind sign, verify) | implemented, matches reference |
| Presentation with key binding | implemented, matches reference |
| Key binding: Schnorr on BLS12-381 G1 | implemented |
| Key binding: `ecdsa-p256-db` (Lehmann) | not implemented — see `PROFILE.md` §4 |
| Per-verifier pseudonyms | not implemented |
| Credential container (JWP profile) | implemented, `src/jwp.rs` |
| UniFFI bindings (Kotlin, Swift) | generated, in `bindings/` |
| C ABI for cgo (Go issuer + verifier) | implemented, smoke-tested from Go |
| Browser package (wasm) | implemented, `make wasm` |

Every value in `test-vectors/emlun_reference.json` was produced by the
reference implementation. The `hardware_keybind` case additionally carries
key binding signatures captured from a real YubiKey prototype, and this
crate reproduces the entire flow around them byte for byte.

## Using it

```rust
use zk_cred_bbs::blind::{BlindSuite, Disclosure, SCHNORR_SUITE_ID};
use zk_cred_bbs::keybind::SchnorrBls12381;
use zk_cred_bbs::suite::{ScalarSource, Suite};

let suite = BlindSuite::new(
    Suite::new(ScalarSource::System),
    SchnorrBls12381,
    SCHNORR_SUITE_ID,
);

// Issuance, holder side. The device signs `challenge` between the halves.
let (state, secret_prover_blind, challenge) =
    suite.commit_init(&committed_messages, &keybind_public_keys)?;
let commitment = suite.commit_finalize(&state, &device_signatures)?;

// Issuance, issuer side.
let signature = suite.blind_sign(&sk, &pk, &commitment, &header, &issuer_messages)?;

// Presentation. Again, the device signs between the halves.
let (state, _info, challenges) = suite.blind_proof_gen_init(
    &pk, &signature, &header, &presentation_header,
    &all_messages, issuer_messages.len(), &disclosures,
    &keybind_public_keys, &secret_prover_blind)?;
let proof = suite.blind_proof_gen_finalize(&state, &device_signatures)?;
```

The `*_init` / `*_finalize` split is not decoration. A device signature
happens in the middle, and `state` is always a serialisable octet string so
it can cross a thread or process boundary — on the web, the computation runs
in a worker while WebAuthn must run on the main thread.

`ScalarSource::System` is the only correct choice outside tests;
`ScalarSource::Seeded` exists so the drafts' own vectors, and the captured
hardware signatures, are reproducible.

## The container

BBS signs an ordered list of opaque octet strings. A credential is a set of
named claims. `src/jwp.rs` is the mapping between the two, plus the wire
format that carries it: a profile of JWP Compact Serialization
(`draft-ietf-jose-json-web-proof-13`) with the credential shape of
`draft-bormann-jwp-modular-bbs-02`.

It lives in this crate rather than in each consumer for one reason. If the
issuer and the wallet derive the message vector differently - a claim
ordered differently, a disclosure index off by one - every proof fails, and
nothing in the failure says why. One implementation cannot disagree with
itself.

Three deliberate divergences from the draft, each documented in the module:
key binding is this profile's Schnorr construction rather than
`ecdsa-p256-db` (a different message layout, so it is refused by name, not
silently accepted); blind-issuance messages get their own `hcmap` because
the draft's `cmap` only names issuer payloads; and `scalar: true` is
rejected rather than half-implemented.

```
issued:     <issuer header> . <payload>~<payload>~... . <signature>
presented:  <presentation header> . <issuer header> . <payload>~~<payload>~... . <proof>
```

Withheld payloads leave their slot empty, so positions are preserved. The
issuer header's octets are the BBS `header` input and are never
re-serialized - a re-encoded header is a different header, and BBS would
verify against the wrong one.

## Bindings

One implementation, four consumers — so a change lands everywhere at once
rather than being ported three more times:

| target | command | consumer |
|---|---|---|
| Kotlin | `make bindings-kotlin` | `siros-sdk-kotlin` |
| Swift | `make bindings-swift` | `siros-sdk-swift` |
| C ABI (cgo) | `make go-cabi` | `vc` issuer and verifier |
| wasm | `make wasm` | `wallet-common` / `wallet-frontend` |

`go-cabi-smoketest/` is a working Go binding over the C ABI, exercised
against the reference vectors by `make go-smoketest`. It is written in the
shape `vc` should adopt — note the `BlindSigner`/`ProofVerifier` interfaces,
so an out-of-process implementation stays a constructor swap.

The C header is hand-written; `make check-go-header` fails the build if it
drifts from `src/go_ffi.rs`, in addition to the compile-time assertions on
the Rust side.

### The two-phase API is not decoration

Both issuance and presentation split around an authenticator signature, and
the intermediate `state` is always a plain octet string so it can cross a
thread, process, or language boundary. In the browser this is load-bearing:
the computation belongs in a worker, but WebAuthn requires the main thread
and a user gesture. Do not add a single-call convenience wrapper — it could
only work by calling WebAuthn from inside the worker, which does not work.

## Building

```sh
cargo test          # includes the conformance and rejection suites
make go-smoketest   # exercises the C ABI from Go
```

## Licence

BSD 2-Clause. See [`LICENSE`](LICENSE).
