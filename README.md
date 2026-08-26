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
| UniFFI / wasm / cgo bindings | not implemented |

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

## Building

```sh
cargo test          # includes the conformance and rejection suites
```

## Licence

BSD 2-Clause. See [`LICENSE`](LICENSE).
