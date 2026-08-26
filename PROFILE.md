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

All four are accommodations to the YubiKey prototype. Each is marked
`DELTA n` in the source.

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

### DELTA 3 — SHA-256 prehash of the key binding challenge

The challenge is `serialize([randomized_key, challenge_scalar])` = 48 + 32 =
80 octets, over the prototype's 64-octet ceiling, so the authenticator is
handed `SHA-256(that)` = 32 octets. (`src/blind.rs`, `blind_proof_gen_init`
and `blind_core_proof_verify`.)

**Open concern, to raise with Emil:** this prehash carries no domain
separation tag. The authenticator ends up signing a bare 32-octet digest it
cannot interpret — a signing oracle if that key handle is ever reachable
from another context. A DST and a per-key-handle scoping rule are worth
adding before this is anything but a prototype.

### DELTA 4 — key binding public keys are negated

RFC 8235 computes `r = v − a·c`; eprint 2025/1995 computes `s = ω + c·sk`.
The two are compatible iff the public key is negated. A wallet registering a
device key produced under the RFC 8235 convention must negate it before
using it as a key binding key.

This crate implements the eprint 2025/1995 convention and takes key binding
public keys already in that form — **the negation is the caller's
responsibility**, matching the reference implementation, which negates at the
call site.

**Open concern:** this is a sign-convention mismatch between two live
specifications. It should be fixed in one of them rather than papered over
by negating in every wallet.

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
cd wallet-common && npm install --ignore-scripts
# copy tools/dump_vectors.test.ts from this repo into src/bbs/
VECTOR_OUT=/path/to/zk-cred-bbs/test-vectors/emlun_reference.json \
  npx vitest run src/bbs/dump_vectors.test.ts
```

The vectors are deterministic because the reference suite is configured with
seeded random scalars (`SEED = "3.141592653589793238462643383279"`), which is
also what makes the captured hardware signatures reproducible.

### Emil's own generator, and why we do not use it directly

`wallet-common` also ships the canonical, spec-formatted generator
(`src/bbs/blind_bbs_test_vectors.ts`, run with `yarn install && yarn run
build && npx node dist/bbs/blind_bbs_test_vectors.js`). It emits the
draft's test-vector appendix rather than JSON, which is why this crate
carries its own dump script instead.

**As of `d0cc03f` that generator does not run.** It aborts with `Invalid
signature` inside `CoreCommitVerify`, reached from `BlindSign`. The cause is
that it was never updated for DELTA 1: at line 91 it still computes

```ts
const keybind_generators = await create_generators(K, "KEYBIND_" || api_id);
```

— the pre-BP1 formula — while `blind_bbs.ts` now uses
`[G1.Point.BASE, ...create_generators(K-1, ...)]`. So it signs against a
different generator than the library verifies against. `git log` on the file
confirms it: its last change is `8a33eca`, which predates all three delta
commits (`3a5f272`, `69f6a9c`, `43200b2`), none of which touched it.

Prepending `G1.Point.BASE` to match the library makes it run to completion.
Reported upstream; noted here because anyone reaching for the canonical
generator will hit this.

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
