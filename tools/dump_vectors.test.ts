/**
 * Not a test: a vector generator. Run with
 *   npx vitest run src/bbs/dump_vectors.test.ts
 * to emit ground-truth JSON for the Rust port (zk-cred-bbs) to check
 * itself against. Lives as a .test.ts purely to reuse the repo's tooling.
 */
import { writeFileSync } from "node:fs";
import { it } from "vitest";

import { concat, fromHex, toHex, toU8, toUtf8 } from "../utils/util";
import { getCipherSuite as getBaseSuite } from ".";
import { DisclosureChoice, getCipherSuite } from "./blind_bbs";

const OUT = process.env.VECTOR_OUT ?? "/tmp/bbs_vectors.json";

const hex = (b: any) => toHex(toU8(b));

// The exact mocked-scalar configuration blind_bbs.test.ts uses for the
// hardware key binding case, so the Rust port can reproduce it bit-exactly.
const MOCK = {
	SEED: toUtf8("3.141592653589793238462643383279"),
	DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_"),
};

it("dump", async () => {
	const base = getBaseSuite('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_');
	const { expand_message } = base.params.hash_to_curve_suite.suiteParams;
	const api_id = toUtf8('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_' + 'H2G_HM2S_');

	const out: any = { api_id: hex(api_id) };

	// --- expand_message_xmd ---------------------------------------------
	out.expand_message_xmd = [];
	for (const [msg, dst, len] of [
		["", "QUUX-V01-CS02-with-expander-SHA256-128", 32],
		["abc", "QUUX-V01-CS02-with-expander-SHA256-128", 32],
		["abcdef0123456789", "QUUX-V01-CS02-with-expander-SHA256-128", 32],
		["abc", "DST", 128],
		["", "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_", 48],
	] as [string, string, number][]) {
		out.expand_message_xmd.push({
			msg: hex(toUtf8(msg)),
			dst: hex(toUtf8(dst)),
			len,
			out: hex(await expand_message(toUtf8(msg), toUtf8(dst), len)),
		});
	}

	// --- hash_to_scalar --------------------------------------------------
	const h2s_dst = concat(api_id, toUtf8("H2S_"));
	out.hash_to_scalar = [];
	for (const msg of ["", "abc", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"]) {
		const m = msg.length === 64 ? fromHex(msg) : toUtf8(msg);
		out.hash_to_scalar.push({
			msg: hex(m),
			dst: hex(h2s_dst),
			scalar: hex(base.serialize([await base.hash_to_scalar(m, h2s_dst)])),
		});
	}

	// --- create_generators ------------------------------------------------
	const generators = await base.create_generators(11, api_id);
	out.create_generators = { count: 11, api_id: hex(api_id), points: generators.map(g => hex(base.serialize([g]))) };

	// --- messages_to_scalars ----------------------------------------------
	const draftMessages = [
		"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
		"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
		"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
		"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
		"496694774c5604ab1b2544eababcf0f53278ff50",
		"515ae153e22aae04ad16f759e07237b4",
		"d183ddc6e2665aa4e2f088af",
		"ac55fb33a75909ed",
		"96012096",
		"",
	].map(fromHex);
	out.messages_to_scalars = {
		messages: draftMessages.map(hex),
		scalars: (await base.messages_to_scalars(draftMessages, api_id)).map(s => hex(base.serialize([s]))),
	};

	// --- base BBS Sign / Verify -------------------------------------------
	const SK = 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn;
	const PK = fromHex(
		"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa1" +
		"36f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d46" +
		"0acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63a" +
		"ebc364cd55ded0c");
	const header = fromHex("11223344556677889900aabbccddeeff");
	out.sign = {
		sk: hex(base.serialize([SK])),
		pk: hex(PK),
		header: hex(header),
		messages: draftMessages.map(hex),
		signature: hex(await base.Bbs.Sign(SK, PK, header, draftMessages)),
	};

	// --- blind BBS with real hardware key binding (the §1.4 case) ---------
	const suite = getCipherSuite('BBS-SCHNORR_BLS12381G1_XMD:SHA-256_SSWU_RO_', { mocked_random_scalars_params: MOCK });
	const { BlindSign, BlindProofGenInit, BlindProofGenFinalize, BlindProofVerify, CommitInit, CommitFinalize } = suite.BlindBbs;
	const { G1 } = suite.params.curves;

	const committed_messages = [
		"5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
		"a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
		"835889a40744813a892eff9deb1edaeb",
		"e1ca9729410dc6ba",
		"",
	].map(fromHex);
	const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");
	const dpk_rfc8235 = G1.Point.fromHex("83b93af60b1e844b992f726dd8d6df0ffe846e83de5b9c3df5705de3bb96c781f98215602bb3a54a757351573066d502");
	const keybind_public_keys = [dpk_rfc8235.negate()];
	const kbpk = keybind_public_keys.map(K => suite.Bbs.serialize([K]));
	const commit_sigs = [fromHex("3513e5517490e2f80bc2812e609aa9ebbebfc1029e5cded759ff65e994f9400b6564af908b0f24a23e30a338047445c60594fb71760cda0108d4c08c4351dabf")];
	const proof_sigs = [fromHex("2696f2595e3026f89618048c4dfbd4d895463828c6d2e57d3d2acce80d89fef30ee68d391ac9769900bdfc07daa6f30f4503fe45c0544749b0701af1e648647c")];

	const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, kbpk);
	const commitment_with_proof = await CommitFinalize(state, commit_sigs);
	const signature = await BlindSign(SK, PK, commitment_with_proof, header, draftMessages);

	const options: DisclosureChoice[] = ["DISCLOSE", "COMMIT", "HIDE"];
	const message_disclosures: DisclosureChoice[] = draftMessages.map((_, i) => options[i % 3]);
	const committed_message_disclosures: DisclosureChoice[] = committed_messages.map((_, i) => options[i % 3]);
	const all_disclosures = [...message_disclosures, ...committed_message_disclosures];

	const [proof_state, , dpk_challenges] = await BlindProofGenInit(
		PK, signature, header, presentation_header,
		[...draftMessages, ...committed_messages], draftMessages.length,
		all_disclosures, kbpk, secret_prover_blind);
	const proof = await BlindProofGenFinalize(proof_state, proof_sigs);
	await BlindProofVerify(PK, proof, header, presentation_header, draftMessages.length,
		[...draftMessages.filter((_, i) => message_disclosures[i] === "DISCLOSE"),
		 ...committed_messages.filter((_, i) => committed_message_disclosures[i] === "DISCLOSE")],
		all_disclosures);

	out.hardware_keybind = {
		mock_seed: hex(MOCK.SEED),
		mock_dst: hex(MOCK.DST),
		sk: hex(suite.Bbs.serialize([SK])),
		pk: hex(PK),
		header: hex(header),
		presentation_header: hex(presentation_header),
		signer_messages: draftMessages.map(hex),
		committed_messages: committed_messages.map(hex),
		keybind_public_keys: kbpk.map(hex),
		keybind_commit_signatures: commit_sigs.map(hex),
		keybind_proof_signatures: proof_sigs.map(hex),
		disclosures: all_disclosures,
		// intermediates, so a Rust failure can be localized
		commit_challenge: hex(suite.Bbs.serialize([challenge])),
		secret_prover_blind: hex(suite.Bbs.serialize([secret_prover_blind])),
		commitment_with_proof: hex(commitment_with_proof),
		signature: hex(signature),
		dpk_challenges: dpk_challenges.map(c => hex(suite.Bbs.serialize([c]))),
		proof: hex(proof),
	};

	writeFileSync(OUT, JSON.stringify(out, null, 2));
	console.log("wrote", OUT);
});
