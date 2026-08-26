# Questions for Emil

Each is tagged with which day-one item it would close (plan §4.4.2), so
anything he answers is something we don't need a token for.

---

## First, a bug report

**`src/bbs/blind_bbs_test_vectors.ts` doesn't run at branch head (`d0cc03f`).**
`yarn install && yarn run build && npx node dist/bbs/blind_bbs_test_vectors.js`
aborts with `Invalid signature` inside `CoreCommitVerify`, reached from
`BlindSign`.

Cause: it was never updated for the BP1 change. Line 91 still has

```ts
const keybind_generators = await create_generators(K, concat(toUtf8("KEYBIND_"), api_id));
```

while `blind_bbs.ts` now uses
`[G1.Point.BASE, ...create_generators(K - 1, ...)].slice(0, K)`. So it signs
against a different generator than the library verifies against. `git log`
on the file agrees — its last change is `8a33eca`, which predates
`3a5f272` (BP1), `69f6a9c` (prehash) and `43200b2` (SEC1); none of them
touched it.

Prepending `G1.Point.BASE` (and destructuring `G1` from
`suite.params.curves`) makes it run to completion and emit the full vector
set.

---

## On the four deltas — are they firmware, or protocol? *(closes item 3)*

These matter because we've implemented all four on the strength of one
captured vector, and three of them look like accommodations that could
change under us.

1. **Is the 64-octet `tbs` ceiling a property of 5.8.1-alpha0, or of
   previewSign itself?** If a later build lifts it, does the SHA-256
   prehash of the key binding challenge go away — and would you treat that
   as a wire-format change, or keep the prehash regardless?

2. **The prehash carries no domain separation tag** —
   `SHA-256(serialize([PK_tilde, challenge]))`. Deliberate? The token will
   Schnorr-sign any 32-octet blob under that key handle, so a DST plus a
   per-key-handle scoping rule looks worth having before this is more than
   a prototype. Is there a reason not to?

3. **The SEC1 uncompressed nonce encoding** — is that the firmware's own
   serialization of `R`, or a choice in the TS to match it? It decides
   whether the CFRG PR should carry it or whether it's a YubiKey-specific
   profile note.

4. **The RFC 8235 vs eprint 2025/1995 sign convention** — the `.negate()`
   in your hardware test. Is there a plan to reconcile that in one of the
   specs, or should every wallet keep negating? If the token returns an
   RFC 8235-convention public key, every implementer will trip on this
   exactly once.

## On what a single captured vector can't contain *(closes item 2)*

5. **Could you dump a `generateKey` response verbatim** — the COSE key and
   the `keyHandle` — from a real token? We've implemented against the shape
   in your `sign_bbs_create.py`, but we're guessing at `kty`, and at
   whether `crv` is `13` or the `-65601` placeholder in practice.

6. **Do you have a second signature over a *different* message from the
   same key handle?** One data point can't distinguish an implementation
   that's correct from one that happens to agree on a single input — this
   is the cheapest thing that would.

## On error behaviour *(closes item 4)*

7. **What does the token return for an over-length `tbs`** — CTAP2 `0x03`,
   or something else? We currently reject over-64 client-side with our own
   error, but matching the real code would be better.

8. **Does a BBS key handle require UV?** And does that differ between NFC
   and USB? (We know both transports work — this is about behaviour, not
   capability.)

---

*Items 5 and 6 from the day-one list are already closed: the tokens support
both USB and NFC, and ARKG and BBS can live on the same token. Worth still
smoke-testing both transports on arrival, since this org has been bitten
once by a transport-looking discrepancy that turned out to be ClientPin
state poisoning — but that's verification, not an open question.*
