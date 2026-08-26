// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// Exercises the real staticlib against the same reference vectors the Rust
// tests use, so a mistake in the hand-written header, in argument order, or
// in the ownership contract surfaces here rather than in a Go service.
package bbs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectors struct {
	HardwareKeybind struct {
		PK                  string   `json:"pk"`
		SK                  string   `json:"sk"`
		Header              string   `json:"header"`
		PresentationHeader  string   `json:"presentation_header"`
		SignerMessages      []string `json:"signer_messages"`
		CommittedMessages   []string `json:"committed_messages"`
		CommitmentWithProof string   `json:"commitment_with_proof"`
		Signature           string   `json:"signature"`
		Proof               string   `json:"proof"`
		Disclosures         []string `json:"disclosures"`
	} `json:"hardware_keybind"`
}

func load(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile("../test-vectors/emlun_reference.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	v := &vectors{}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func decodeAll(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(in))
	for i, s := range in {
		out[i] = unhex(t, s)
	}
	return out
}

func disclosures(t *testing.T, names []string) []Disclosure {
	t.Helper()
	out := make([]Disclosure, len(names))
	for i, n := range names {
		switch n {
		case "DISCLOSE":
			out[i] = Disclose
		case "HIDE":
			out[i] = Hide
		case "COMMIT":
			out[i] = Commit
		default:
			t.Fatalf("unknown disclosure %q", n)
		}
	}
	return out
}

// The issuer path. The signature must match what the Rust and TypeScript
// implementations produce, byte for byte, over the C ABI.
func TestBlindSignMatchesReference(t *testing.T) {
	hw := load(t).HardwareKeybind

	got, err := Native{}.BlindSign(SuiteSchnorr,
		unhex(t, hw.SK), unhex(t, hw.PK),
		unhex(t, hw.CommitmentWithProof), unhex(t, hw.Header),
		decodeAll(t, hw.SignerMessages))
	if err != nil {
		t.Fatalf("BlindSign: %v", err)
	}
	if hex.EncodeToString(got) != hw.Signature {
		t.Fatalf("signature mismatch over the C ABI\n got: %s\nwant: %s",
			hex.EncodeToString(got), hw.Signature)
	}
}

func TestBlindSignRejectsBadCommitment(t *testing.T) {
	hw := load(t).HardwareKeybind

	commitment := unhex(t, hw.CommitmentWithProof)
	commitment[len(commitment)-1] ^= 0x01

	_, err := Native{}.BlindSign(SuiteSchnorr,
		unhex(t, hw.SK), unhex(t, hw.PK), commitment, unhex(t, hw.Header),
		decodeAll(t, hw.SignerMessages))
	if err == nil {
		t.Fatal("issuer blind-signed a commitment with a corrupted key binding signature")
	}
}

func TestVerifyProof(t *testing.T) {
	hw := load(t).HardwareKeybind
	disc := disclosures(t, hw.Disclosures)

	all := append(decodeAll(t, hw.SignerMessages), decodeAll(t, hw.CommittedMessages)...)
	var disclosed [][]byte
	for i, m := range all {
		if disc[i] == Disclose {
			disclosed = append(disclosed, m)
		}
	}

	verify := func(proof []byte) error {
		return Native{}.VerifyProof(SuiteSchnorr, unhex(t, hw.PK), proof,
			unhex(t, hw.Header), unhex(t, hw.PresentationHeader),
			len(hw.SignerMessages), disclosed, disc)
	}

	if err := verify(unhex(t, hw.Proof)); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}

	bad := unhex(t, hw.Proof)
	bad[len(bad)/2] ^= 0x01
	if err := verify(bad); err == nil {
		t.Fatal("a tampered proof was accepted")
	}
}

// An unknown suite selector must be an error, not a silent fallback to a
// suite the caller did not ask for.
func TestUnknownSuiteIsRejected(t *testing.T) {
	hw := load(t).HardwareKeybind
	verifier := Native{}
	err := verifier.VerifyProof(Suite(99), unhex(t, hw.PK), unhex(t, hw.Proof),
		nil, nil, 0, nil, nil)
	if err == nil {
		t.Fatal("an unknown suite selector was accepted")
	}
}

// Repeated calls must not corrupt state or leak in a way that breaks the
// next call — the cheapest available check that the ownership contract holds.
func TestRepeatedCallsAreStable(t *testing.T) {
	hw := load(t).HardwareKeybind
	signer := Native{}
	for i := 0; i < 50; i++ {
		_, err := signer.BlindSign(SuiteSchnorr,
			unhex(t, hw.SK), unhex(t, hw.PK),
			unhex(t, hw.CommitmentWithProof), unhex(t, hw.Header),
			decodeAll(t, hw.SignerMessages))
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}
