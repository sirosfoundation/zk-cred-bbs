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
const { initSync, commitInit, commitFinalize } = await import(join(pkg, 'zk_cred_bbs.js'));

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

if (process.exitCode) {
  console.error('\nthe built package does not work');
} else {
  console.log('\nthe built package initialises and computes');
}
