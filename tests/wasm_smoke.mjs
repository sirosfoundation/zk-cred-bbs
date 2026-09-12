// Loads the built browser package the way a consumer does, and runs a real
// commit round trip through it.
//
// CI already greps pkg/zk_cred_bbs.js for the expected export names. That
// catches a renamed or dropped binding and nothing else: a package whose
// wasm fails to instantiate, or whose functions throw on every input,
// exports exactly the same symbols. This is the part that only running it
// can tell you.
//
// Usage: node tests/wasm_smoke.mjs   (after `make wasm`)
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const pkg = join(dirname(fileURLToPath(import.meta.url)), '..', 'pkg');
const {
  initSync,
  commitInit,
  commitFinalize,
  jwpCommittedMessages,
  jwpInspect,
  jwpAccept,
  jwpPresentInit,
  jwpPresentFinalize,
  jwpVerify,
  jwpBuildPresentationHeader,
} = await import(join(pkg, 'zk_cred_bbs.js'));

// `--target web` ships an async default init that fetches the .wasm over
// HTTP. initSync takes the bytes directly, which is what works off a
// filesystem.
initSync({ module: readFileSync(join(pkg, 'zk_cred_bbs_bg.wasm')) });

const SUITE = 'schnorr';
const enc = new TextEncoder();
const messages = [enc.encode('device_pin_hash-value'), enc.encode('recovery-secret')];

function check(label, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) process.exitCode = 1;
}

// A throw from one group is a failure of that group, not of the run: an
// unhandled one would abort the file and silently skip every check after
// it, which is exactly when you most want to see the rest.
function group(label, fn) {
  try {
    fn();
  } catch (e) {
    check(label, false, e.message ?? String(e));
  }
}

// An unbound commitment: no key binding keys, so no signatures to finalize
// with. This is the case a wallet uses when the credential is bound to no
// device key, and the one most likely to be got wrong by an empty-array
// bug on either side of the boundary.
const init = commitInit(SUITE, messages, []);
check('commitInit returns a state', init.state.length > 0, `${init.state.length} bytes`);
check('secretProverBlind is a scalar', init.secretProverBlind.length === 32);
check('challenge is a scalar', init.challenge.length === 32);

const commitment = commitFinalize(SUITE, init.state, []);
check('commitFinalize returns a commitment', commitment.length > 0, `${commitment.length} bytes`);

// The blinding factor is the credential's long-term secret. Repeating it
// across two commits would mean the RNG is not wired through to the wasm
// build at all - which is a real failure mode here, since the browser
// build needs getrandom's wasm_js backend and silently has no entropy
// source without it.
const again = commitInit(SUITE, messages, []);
check(
  'blinding factor is fresh per commit',
  Buffer.compare(Buffer.from(init.secretProverBlind), Buffer.from(again.secretProverBlind)) !== 0,
);

// A suite name the crate does not know must be rejected, not silently
// treated as a default.
let rejected = false;
try {
  commitInit('not-a-suite', messages, []);
} catch {
  rejected = true;
}
check('an unknown suite is rejected', rejected);

// ── The credential-level API ────────────────────────────────────────
//
// Against test-vectors/sdk_jwp_fixture.json — the same file the Kotlin and
// Swift SDKs test against, and the same one the Go relying party verifies.
// That is the point of running it here: agreement between the bindings is
// the property that matters, and a fixture shared with them is the only
// thing that actually demonstrates it. A browser-only round trip would
// pass just as happily with a browser-only claim ordering.
const fixture = JSON.parse(readFileSync(join(pkg, '..', 'test-vectors', 'sdk_jwp_fixture.json'), 'utf8'));
const unhex = (h) => Uint8Array.from(Buffer.from(h, 'hex'));

for (const [name, suite] of [
  ['plain', 'plain'],
  ['keybind', 'schnorr'],
]) {
  group(`${name}: credential checks`, () => {
    const c = fixture.cases[name];
    const pk = unhex(c.issuer_pk);
    const committed = c.committed_messages.map(unhex);
    const keybindKeys = c.keybind_public_keys.map(unhex);
    const blind = unhex(c.secret_prover_blind);

    const info = jwpInspect(c.issued_jwp);
    check(
      `${name}: jwpInspect reads the container`,
      info.vct === c.vct &&
        info.numSignerMessages === c.num_signer_messages &&
        JSON.stringify(info.pointers) === JSON.stringify(c.pointers),
      info.vct,
    );

    // The real check: the signature verifies over the messages this binding
    // built, in the order it built them. A claim-ordering disagreement with
    // the native SDKs fails right here.
    const accepted = jwpAccept(suite, c.issued_jwp, pk, committed, keybindKeys, blind);
    check(`${name}: jwpAccept verifies the issuer's signature`, accepted.vct === c.vct);

    // ...and that it is a real check, not a function that returns success.
    let tampered = false;
    const wrongPk = unhex(c.issuer_pk);
    wrongPk[wrongPk.length - 1] ^= 1;
    try {
      jwpAccept(suite, c.issued_jwp, wrongPk, committed, keybindKeys, blind);
    } catch {
      tampered = true;
    }
    check(`${name}: jwpAccept rejects a wrong issuer key`, tampered);
  });
}

// A full presentation round trip, browser-side. Only the unbound case:
// the other needs an authenticator signature, which is exactly the part
// that does not happen in a worker.
const plain = fixture.cases.plain;
group('presentation round trip', () => {
  const ph = jwpBuildPresentationHeader('smoke-nonce', 'https://verifier.test', null);
  check('jwpBuildPresentationHeader returns header octets', ph.length > 0, `${ph.length} bytes`);

  const disclose = ['/given_name', '/address/country'];
  const present = jwpPresentInit(
    'plain',
    plain.issued_jwp,
    unhex(plain.issuer_pk),
    ph,
    disclose,
    plain.committed_messages.map(unhex),
    [],
    unhex(plain.secret_prover_blind),
  );
  check(
    'jwpPresentInit returns transferable state',
    present.state.length > 0,
    `${present.state.length} bytes`,
  );
  check('jwpPresentInit needs no signatures when unbound', present.keybindChallenges.length === 0);

  const presented = jwpPresentFinalize('plain', present.state, []);
  const result = jwpVerify('plain', presented, unhex(plain.issuer_pk));
  check('jwpVerify accepts the presentation this package produced', result.vct === plain.vct);
  check(
    'jwpVerify discloses exactly what was asked for',
    JSON.stringify(Object.keys(result.disclosed).sort()) === JSON.stringify([...disclose].sort()),
    Object.keys(result.disclosed).join(', '),
  );
  check('a withheld claim is absent, not null', !('/birth_date' in result.disclosed));
  check('disclosed values are JSON, not strings', result.disclosed['/given_name'] === 'Alice');

  // The fixture's own presentation, made by the Rust side, verified here.
  // Cross-binding in the other direction: this package reading what another
  // one wrote.
  const theirs = jwpVerify('plain', plain.presented_jwp, unhex(plain.issuer_pk));
  check('jwpVerify accepts a presentation made by another binding', theirs.vct === plain.vct);

  // The claim-to-message mapping, which is the thing a TypeScript
  // reimplementation would get subtly wrong.
  const holder = jwpCommittedMessages(JSON.stringify({ device_pin_hash: 'abc123' }));
  check(
    'jwpCommittedMessages names the holder claims',
    JSON.stringify(holder.pointers) === JSON.stringify(plain.holder_pointers),
    holder.pointers.join(', '),
  );
  check(
    'jwpCommittedMessages returns one message per pointer',
    holder.messages.length === holder.pointers.length,
  );
});

if (process.exitCode) {
  console.error('\nthe built package does not work');
} else {
  console.log('\nthe built package initialises and computes');
}
