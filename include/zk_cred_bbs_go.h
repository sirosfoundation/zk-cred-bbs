/* Copyright 2026 SIROS Foundation. BSD 2-Clause License.
 *
 * C ABI for zk-cred-bbs, for Go (cgo) callers.
 *
 * HAND-MAINTAINED. Keep in sync with src/go_ffi.rs. The Rust side carries
 * compile-time assertions on every constant below, and `make check-go-header`
 * re-checks this file against them, so a drift fails the build rather than
 * corrupting an ABI silently.
 *
 * Two entry points, matching the two things a Go service does with BBS:
 *   - an issuer verifies a holder's commitment and blind-signs it;
 *   - a verifier checks a presentation.
 * Nothing on the holder's side is exposed; no Go service commits or proves.
 *
 * There are no handles: BBS has no proving key to load and no circuit to
 * compile, so every call is bytes in, bytes out. Buffers written to *_out
 * parameters are owned by the caller and released with the matching free
 * function.
 */

#ifndef ZK_CRED_BBS_GO_H
#define ZK_CRED_BBS_GO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. */
#define ZK_CRED_BBS_OK 0
#define ZK_CRED_BBS_ERR (-1)
#define ZK_CRED_BBS_PANIC (-2)

/* Suite selectors. */
#define ZK_CRED_BBS_SUITE_PLAIN 0u
#define ZK_CRED_BBS_SUITE_SCHNORR 1u

/* Per-message disclosure codes. */
#define ZK_CRED_BBS_DISCLOSE 0
#define ZK_CRED_BBS_HIDE 1
#define ZK_CRED_BBS_COMMIT 2

/* Issuer: verify the commitment (including each authenticator's proof of
 * possession) and blind-sign it.
 *
 * On ZK_CRED_BBS_OK, *signature_out / *signature_len_out own a buffer to be
 * released with zk_cred_bbs_free_buffer.
 * On failure, *error_out (if non-NULL) owns a message to be released with
 * zk_cred_bbs_free_error_string. */
int32_t zk_cred_bbs_blind_sign(uint32_t suite,
                               const uint8_t *secret_key, size_t secret_key_len,
                               const uint8_t *public_key, size_t public_key_len,
                               const uint8_t *commitment_with_proof,
                               size_t commitment_with_proof_len,
                               const uint8_t *header, size_t header_len,
                               const uint8_t *const *messages_ptrs,
                               const size_t *messages_lens,
                               size_t messages_count,
                               uint8_t **signature_out,
                               size_t *signature_len_out,
                               char **error_out);

/* Verifier: check a presentation. Returns ZK_CRED_BBS_OK only if the proof
 * is valid for exactly these disclosed messages, disclosure pattern,
 * headers and issuer key. */
int32_t zk_cred_bbs_blind_proof_verify(uint32_t suite,
                                       const uint8_t *public_key, size_t public_key_len,
                                       const uint8_t *proof, size_t proof_len,
                                       const uint8_t *header, size_t header_len,
                                       const uint8_t *presentation_header,
                                       size_t presentation_header_len,
                                       size_t issuer_known_messages_no,
                                       const uint8_t *const *disclosed_ptrs,
                                       const size_t *disclosed_lens,
                                       size_t disclosed_count,
                                       const uint8_t *disclosures,
                                       size_t disclosures_len,
                                       char **error_out);

/* Release a buffer written to a *_out / *_len_out pair. */
void zk_cred_bbs_free_buffer(uint8_t *ptr, size_t len);

/* Release an error string written to an error_out parameter. NULL-safe. */
void zk_cred_bbs_free_error_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ZK_CRED_BBS_GO_H */
