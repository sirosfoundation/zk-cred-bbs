# SIROS BBS key binding profile v0

Status: **frozen for implementation, not for interoperability.** Every
identifier below is a placeholder, and three of the four deviations in §3
exist only because of prototype authenticator firmware. Expect all of it to
move.

This document is the phase-0 deliverable of
`~/.claude/plans/bbs-native-sdk-plan.md`: it pins exactly what this crate
implements, so that a Rust port, a TypeScript reference, a Go issuer, and an
authenticator can be checked against one another rather than against each
other's source code.

## 1. Provenance

The construction is Emil Lundberg's, from
[`emlun/wallet-common@blind-bbs-schnorr`](https://github.com/emlun/wallet-common/tree/blind-bbs-schnorr/src/bbs)
(TypeScript, on `@noble/curves`). That implementation is the normative
reference for this crate; where the two disagree, the TypeScript is right
and this crate has a bug.

It builds on:

- `draft-irtf-cfrg-bbs-signatures-08` — base BBS.
- `draft-irtf-cfrg-bbs-blind-signatures` — blind issuance.
- [cfrg/draft-irtf-cfrg-bbs-blind-signatures#48](https://github.com/cfrg/draft-irtf-cfrg-bbs-blind-signatures/pull/48)
  — Emil's key binding extension.
- [eprint 2025/1995](https://eprint.iacr.org/2025/1995) — the Schnorr
  formulation the key binding signature follows.

## 2. Suites

| suite | api_id | key binding |
|---|---|---|
| `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_` | `…_H2G_HM2S_` | none (base BBS) |
| blind, no key binding | `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_` | none |
| blind + Schnorr | `BBS-SCHNORR_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_` | `SchnorrBls12381` |

**The blind layer uses its own api_id.** `messages_to_scalars`,
`create_generators`, `calculate_domain` and every `hash_to_scalar` DST inside
blind issuance and presentation are domain-separated under the *blind*
api_id, not the base one. Mixing them produces values that verify against
nothing — this was the first real bug found while porting.

Derived generator domains, all prefixes on the blind api_id:

- `BLIND_` — blind message generators (`Q_2`, `J_1..J_M`)
- `KEYBIND_` — key binding generators 2..K (see DELTA 1 for generator 1)
- `COM_DIS_` — the two Pedersen generators `Y_0`, `Y_1` for `COMMIT`
  disclosures

## 3. Deviations from the CFRG PR

Each is marked `DELTA n` in the source. Three are accommodations to the
YubiKey prototype; DELTA 3 turns out not to be — see its own note.

### DELTA 1 — BP1 as the first key binding generator

```
keybind_generators = [G1::GENERATOR] ++ create_generators(K-1, "KEYBIND_" || api_id)
```

An authenticator can only scalar-multiply the curve's standard base point,
not a suite-derived generator, so key binding key #0 must live on it.
(`src/blind.rs`, `keybind_generators`.)

### DELTA 2 — SEC1 uncompressed nonce encoding

The Schnorr nonce point `R` is hashed as `0x04 || x || y` (97 octets),
**not** BBS's 48-octet Zcash-compact form, because that is what the
firmware hashes. (`src/keybind.rs`, `serialize_nonce_point`.)

**The one delta with an expiry date.** Emil, 2026-08-27: this is the current
firmware's serialization, chosen because they already had it implemented and
needed it in time for the demo. The firmware team has been alerted that they
will want to **migrate to the compact serialization before a more mature
release**. So this should *not* go into the CFRG PR — it is a
YubiKey-prototype profile note, and a temporary one.

When the firmware migrates, `serialize_nonce_point` collapses to
`Bbs.serialize([R])` and this delta disappears. Note what that does and does
not invalidate: the encoding only affects the per-presentation Schnorr
challenge, so **already-issued credentials survive** — the key binding public
key baked into a credential is just a point, unaffected. Only code that
verifies a signature from that authenticator has to move, and a mixed fleet
would need both encodings selectable.

### DELTA 3 — prehash of the key binding challenge

The challenge is `serialize([randomized_key, challenge_scalar])` = 48 + 32 =
80 octets, over the authenticator's input ceiling, so it is handed
`SHA-256(that)` = 32 octets. (`src/blind.rs`, `blind_proof_gen_init` and
`blind_core_proof_verify`.)

**Not a prototype artifact — reclassify it.** Emil answered both halves of
this on 2026-08-27:

- **The 64-octet ceiling belongs to 5.8.1-alpha0, not to previewSign**,
  which imposes no input-size limit of its own. But some bound will likely
  always exist on a hardware signer — "definitely not above 1 kB", his
  guess ≤128 octets — so **a prehash stays in the spec regardless**, for
  wide hardware-signer compatibility rather than as a workaround for one
  firmware build.
- **The missing DST is going to CFRG** alongside the ceiling question. The
  likely outcome is `BBS.hash_to_scalar` (or similar) in place of bare
  SHA-256, which brings a DST with it.

So expect the prehash to *stay* and its *form* to change. That is a wire
change and needs a profile-version bump when it lands (§2's
`siros-bbs-kb-schnorr-v0`), not a silent swap.

Worth being precise about the blast radius: `hash_to_scalar` output
serializes to 32 octets, the same width as a SHA-256 digest, so the
authenticator-facing contract — *sign exactly 32 octets* — does not move.
The change is confined to how this crate computes the challenge; nothing in
the WSCD layer or on the CTAP2 wire changes with it.

### DELTA 4 — key binding public keys are negated

RFC 8235 computes `r = v − a·c`; eprint 2025/1995 computes `s = ω + c·sk`.
The two are compatible iff the public key is negated.

**This one is permanent, and it is per-authenticator.** Emil's answer,
2026-08-27: there is no plan to reconcile the two conventions yet — he
intends to survey existing hardware Schnorr/BLS implementations, and the
outcome may inform which the spec picks. But **whichever it picks, a
non-zero number of implementations will land on the other side**, so the
spec has to call the conversion out rather than legislate it away.

The practical consequence is that "does this key need negating" is a
property of the authenticator that produced it, not a global constant, and
it belongs with the stored key rather than at a call site.

Use [`keybind::keybind_public_key_from_coordinates`] rather than doing it by
hand. A real 5.8.1-alpha0 `generateKey` output reports the public key as an
**EC2-style pair of 48-octet coordinates at COSE `-2`/`-3`** — not as a
single compressed point — and follows the RFC 8235 convention, so both a
re-encoding and the negation are needed. Each is silent when wrong: reading
`-2` alone gives something the right length with the right leading bytes,
and skipping the negation gives a perfectly valid point that just verifies
nothing. `tests/hardware_capture.rs` pins both against the real capture.

## 4. Key binding is a seam, and it is not only a signature algorithm

`SignatureScheme` (`src/keybind.rs`) abstracts the key binding signature.
That is enough to swap Schnorr for something else *of the same shape*, but
it is **not** enough to reach `ecdsa-p256-db`, the construction
`draft-bormann-jwp-modular-bbs` actually specifies:

- **This profile** puts key binding public keys in the *commitment*, with
  dedicated `KEYBIND_` generators.
- **`ecdsa-p256-db`** reserves *four message slots* for the device public
  key's x and y coordinates as 128-bit limbs.

Different credential message layouts, not just different signatures.
Supporting both means two layouts, decided at issuance.

## 5. Regenerating the reference vectors

`test-vectors/emlun_reference.json` is generated, not transcribed. To
reproduce it:

```sh
git clone -b blind-bbs-schnorr https://github.com/emlun/wallet-common.git
cd wallet-common && git checkout edc791c   # or later
yarn install
# copy tools/dump_vectors.test.ts from this repo into src/bbs/
VECTOR_OUT=/path/to/zk-cred-bbs/test-vectors/emlun_reference.json \
  npx vitest run src/bbs/dump_vectors.test.ts
```

The vectors are deterministic because the reference suite is configured with
seeded random scalars (`SEED = "3.141592653589793238462643383279"`), which is
also what makes the captured hardware signatures reproducible.

### Reproducibility

The whole file regenerates byte-identically. Two things make that true, and
both are load-bearing:

- the suite runs with **seeded random scalars**
  (`SEED = "3.141592653589793238462643383279"`), which is also what makes
  the captured hardware signatures reproducible; and
- the software key binding signatures in `multi_keybind` are produced with
  a **deterministic Schnorr nonce**, the same construction Emil's own
  generator uses (`hash_to_scalar(serialize([SK, i]) || message,
  "TEST-VECTORS_" || api_id)`). `Sig.Sign` otherwise draws a fresh random
  nonce, which would change the signatures — and therefore
  `commitment_with_proof` and `proof` — on every run, so a regenerated file
  would diff against the committed one and look like a regression.

### Emil's own generator

`wallet-common` also ships the canonical, spec-formatted generator
(`src/bbs/blind_bbs_test_vectors.ts`, run with `yarn install && yarn run
build && npx node dist/bbs/blind_bbs_test_vectors.js`). It emits the draft's
test-vector appendix rather than JSON, which is why this crate carries its
own dump script instead.

It was broken between `8a33eca` and `d0cc03f` — it aborted with `Invalid
signature` in `CoreCommitVerify`, because it had never been updated for
DELTA 1 and still used the pre-BP1 `create_generators(K, "KEYBIND_")`, so it
signed against a different generator than the library verified against.
**Fixed upstream in `edc791c`** ("fixup! Use BP1 as first key binding
generator"), which also corrects the generator's own emitted documentation
line. That commit touches only the generator, not `blind_bbs.ts` — verified
here by regenerating the vectors across it and confirming every
deterministic value is byte-identical.

## 6. What the hardware vector actually proves

`hardware_keybind` in the vector file carries two signature constants
produced by a real YubiKey prototype via
[`emlun/python-fido2@bbs-schnorr`](https://github.com/emlun/python-fido2/tree/bbs-schnorr)
(`examples/sign_bbs_create.py`, `examples/sign_bbs_sign.py`). This crate
reproduces the full flow around them — commit, blind sign, verify, prove,
verify — byte for byte.

That is a strong conformance result and a weak hardware result. It proves
this port agrees with the reference implementation on data a real
authenticator produced. It does **not** exercise key generation, a second
message, any error path, or any firmware behaviour, because that needs the
token — and as of 2026-08-26 this org has no token on the required
firmware. See the plan's §4.4.1.

It also cannot exercise more than one key binding key. The `multi_keybind`
vectors cover K = 1, 2 and 3 with software keys for exactly that reason:
keybind generator 0 is BP1 (DELTA 1) while 1..K-1 come from
`create_generators(K-1, "KEYBIND_")`, so everything past the first key is a
path the hardware case never reaches.

Relevant CTAP2 wire details, for whoever implements the authenticator side:

- firmware: **YubiKey 5.8.1-alpha0** (confirmed by Emil Lundberg,
  2026-08-26). Note this is a *newer* alpha than the one this org's
  existing ARKG/previewSign work ran against, so holding a previewSign
  prototype token does not imply holding a BBS-capable one — check
  `ykman info` for that exact version.
- `previewSign` extension, `{"generateKey": {"algorithms": [-65609]}}`
- COSE alg **-65609** = `EcsdsaBls12_381_BP1_Sha256_SEC1` (placeholder),
  curve 13 or placeholder -65601; public key in COSE `-2` as a 48-octet
  compressed G1 point
- `signByCredential` → `{keyHandle, tbs}` → 64 raw octets
  (`serialize([k_hat, c])`), **not** DER

## 7. Library choice

`bls12_381_plus` 0.9 (MIT/Apache-2.0), a maintained fork of
`zkcrypto/bls12_381`. Chosen because:

- pure Rust, no C dependency;
- hash-to-curve on a current `digest` version — zkcrypto's own 0.8 pins
  `digest` 0.9 and will not compose with `sha2` 0.10;
- `Scalar::from_okm` is exactly BBS's `OS2IP(uniform_bytes) mod r` over a
  48-octet big-endian input (verified against its implementation, which
  combines two big-endian 192-bit digits as `d0·2^192 + d1`);
- `to_be_bytes`/`from_be_bytes` give I2OSP/OS2IP directly, and
  `from_be_bytes` rejects non-canonical encodings, which is the drafts' own
  `>= r` check;
- `to_compressed` is the 48-octet Zcash encoding BBS uses, and
  `to_uncompressed` gives the `x || y` needed for DELTA 2.

`expand_message_xmd` is implemented in this crate rather than taken from the
curve library: the BBS drafts call it directly for `hash_to_scalar` and
seeded random scalars, not only inside hash-to-curve.
