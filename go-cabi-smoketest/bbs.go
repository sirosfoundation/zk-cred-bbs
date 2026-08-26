// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// Package bbs is a thin cgo binding over zk-cred-bbs's C ABI, covering the
// two operations a Go service performs: an issuer verifying a holder's
// commitment and blind-signing it, and a verifier checking a presentation.
//
// It lives here as a smoke test for the ABI, but it is written to be the
// shape vc should adopt — note the Signer/Verifier interfaces, which exist
// so an out-of-process implementation would be a constructor swap rather
// than a rewrite of every call site.
package bbs

/*
#include <stdlib.h>
#include "zk_cred_bbs_go.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Suite selects the key binding construction and its domain separation.
type Suite uint32

const (
	// SuitePlain is blind BBS with no device binding.
	SuitePlain Suite = C.ZK_CRED_BBS_SUITE_PLAIN
	// SuiteSchnorr is the Schnorr-on-BLS12-381-G1 device binding profile.
	SuiteSchnorr Suite = C.ZK_CRED_BBS_SUITE_SCHNORR
)

// Disclosure is a per-message disclosure choice.
type Disclosure uint8

const (
	// Disclose reveals the message to the verifier.
	Disclose Disclosure = C.ZK_CRED_BBS_DISCLOSE
	// Hide proves knowledge without revealing.
	Hide Disclosure = C.ZK_CRED_BBS_HIDE
	// Commit hides the message and emits a Pedersen commitment.
	Commit Disclosure = C.ZK_CRED_BBS_COMMIT
)

// ErrVerification is returned when a proof or commitment does not verify.
// It carries no detail about which check failed by design.
var ErrVerification = errors.New("bbs: verification failed")

// BlindSigner is the issuer-side seam. The cgo implementation below
// satisfies it; an out-of-process implementation would too.
type BlindSigner interface {
	BlindSign(suite Suite, secretKey, publicKey, commitment, header []byte, messages [][]byte) ([]byte, error)
}

// ProofVerifier is the verifier-side seam.
type ProofVerifier interface {
	VerifyProof(suite Suite, publicKey, proof, header, presentationHeader []byte,
		issuerKnownMessages int, disclosedMessages [][]byte, disclosures []Disclosure) error
}

// Native is the cgo-backed implementation of both seams.
type Native struct{}

var (
	_ BlindSigner   = Native{}
	_ ProofVerifier = Native{}
)

// cBytes borrows a Go slice for the duration of one call. The Rust side
// never retains the pointer, and runtime.KeepAlive on the caller's side
// keeps the backing array live across the call.
func cBytes(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

// byteArrays copies a [][]byte into C memory as the (ptrs, lens, count)
// triple the ABI takes. Copying is required: Go pointers may not be stored
// in C-allocated memory.
func byteArrays(items [][]byte) (**C.uint8_t, *C.size_t, C.size_t, func()) {
	if len(items) == 0 {
		return nil, nil, 0, func() {}
	}
	ptrs := C.malloc(C.size_t(len(items)) * C.size_t(unsafe.Sizeof(uintptr(0))))
	lens := C.malloc(C.size_t(len(items)) * C.size_t(unsafe.Sizeof(C.size_t(0))))
	ptrSlice := unsafe.Slice((**C.uint8_t)(ptrs), len(items))
	lenSlice := unsafe.Slice((*C.size_t)(lens), len(items))
	copies := make([]unsafe.Pointer, len(items))
	for i, item := range items {
		if len(item) == 0 {
			copies[i] = C.malloc(1)
			ptrSlice[i] = (*C.uint8_t)(copies[i])
			lenSlice[i] = 0
			continue
		}
		copies[i] = C.CBytes(item)
		ptrSlice[i] = (*C.uint8_t)(copies[i])
		lenSlice[i] = C.size_t(len(item))
	}
	return (**C.uint8_t)(ptrs), (*C.size_t)(lens), C.size_t(len(items)), func() {
		for _, p := range copies {
			C.free(p)
		}
		C.free(ptrs)
		C.free(lens)
	}
}

// takeError consumes an owned error string from the ABI.
func takeError(p *C.char) string {
	if p == nil {
		return ""
	}
	msg := C.GoString(p)
	C.zk_cred_bbs_free_error_string(p)
	return msg
}

func statusError(status C.int32_t, msg string) error {
	switch status {
	case C.ZK_CRED_BBS_PANIC:
		return fmt.Errorf("bbs: panic across FFI boundary: %s", msg)
	default:
		if msg == "" {
			msg = "unknown error"
		}
		return fmt.Errorf("%w: %s", ErrVerification, msg)
	}
}

// BlindSign verifies the holder's commitment — including each
// authenticator's proof of possession of its key binding key — and blind
// signs it. A commitment that does not check out is rejected, not signed.
func (Native) BlindSign(suite Suite, secretKey, publicKey, commitment, header []byte, messages [][]byte) ([]byte, error) {
	msgPtrs, msgLens, msgCount, free := byteArrays(messages)
	defer free()

	skPtr, skLen := cBytes(secretKey)
	pkPtr, pkLen := cBytes(publicKey)
	comPtr, comLen := cBytes(commitment)
	hdrPtr, hdrLen := cBytes(header)

	var sigOut *C.uint8_t
	var sigLen C.size_t
	var errOut *C.char

	status := C.zk_cred_bbs_blind_sign(
		C.uint32_t(suite),
		skPtr, skLen, pkPtr, pkLen, comPtr, comLen, hdrPtr, hdrLen,
		msgPtrs, msgLens, msgCount,
		&sigOut, &sigLen, &errOut,
	)
	runtime.KeepAlive(secretKey)
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(commitment)
	runtime.KeepAlive(header)

	if status != C.ZK_CRED_BBS_OK {
		return nil, statusError(status, takeError(errOut))
	}
	takeError(errOut)
	sig := C.GoBytes(unsafe.Pointer(sigOut), C.int(sigLen))
	C.zk_cred_bbs_free_buffer(sigOut, sigLen)
	return sig, nil
}

// VerifyProof returns nil only if the proof is valid for exactly these
// disclosed messages, disclosure pattern, headers and issuer key.
func (Native) VerifyProof(suite Suite, publicKey, proof, header, presentationHeader []byte,
	issuerKnownMessages int, disclosedMessages [][]byte, disclosures []Disclosure) error {

	discPtrs, discLens, discCount, free := byteArrays(disclosedMessages)
	defer free()

	codes := make([]byte, len(disclosures))
	for i, d := range disclosures {
		codes[i] = byte(d)
	}

	pkPtr, pkLen := cBytes(publicKey)
	prPtr, prLen := cBytes(proof)
	hdrPtr, hdrLen := cBytes(header)
	phPtr, phLen := cBytes(presentationHeader)
	codePtr, codeLen := cBytes(codes)

	var errOut *C.char
	status := C.zk_cred_bbs_blind_proof_verify(
		C.uint32_t(suite),
		pkPtr, pkLen, prPtr, prLen, hdrPtr, hdrLen, phPtr, phLen,
		C.size_t(issuerKnownMessages),
		discPtrs, discLens, discCount,
		codePtr, codeLen,
		&errOut,
	)
	runtime.KeepAlive(publicKey)
	runtime.KeepAlive(proof)
	runtime.KeepAlive(header)
	runtime.KeepAlive(presentationHeader)
	runtime.KeepAlive(codes)

	if status != C.ZK_CRED_BBS_OK {
		return statusError(status, takeError(errOut))
	}
	takeError(errOut)
	return nil
}
