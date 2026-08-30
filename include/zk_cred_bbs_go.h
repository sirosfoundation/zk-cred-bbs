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
 *   - an issuer verifies a holder's commitment and blind-signs it
 *     (zk_cred_bbs_jwp_issue);
 *   - a verifier checks a presentation (zk_cred_bbs_jwp_verify).
 * Nothing on the holder's side is exposed; no Go service commits or proves.
 *
 * zk_cred_bbs_blind_sign and zk_cred_bbs_blind_proof_verify are the raw
 * algebra underneath those two, taking and returning an ordered list of
 * opaque messages. They stay exported for test harnesses, but a service
 * should call the container functions: the mapping from named claims to
 * that message list must be byte-identical in the issuer, the wallet and
 * the verifier, and doing it in Go would be a second implementation of the
 * one thing most worth having only one of.
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

/* Key binding selector for zk_cred_bbs_jwp_issue. */
#define ZK_CRED_BBS_KEYBIND_NONE 0u
#define ZK_CRED_BBS_KEYBIND_SCHNORR 1u

/* Issuer: verify the commitment, blind-sign it together with the issuer's
 * own claims, and return a finished JWP in Compact Serialization.
 *
 * issuer_claims_json is a JSON OBJECT - the claims the issuer asserts,
 * values and all. holder_pointers_json is a JSON ARRAY of RFC 6901 pointer
 * strings - the names of the claims the holder committed to, whose values
 * the issuer never sees. Pass "[]" when there are none.
 *
 * extra_header_json may be NULL (with length 0); when given it is a JSON
 * object merged into the Issuer Header (iss, iat, exp, ...) and may not
 * restate alg, vct, kb, cmap or hcmap.
 *
 * On ZK_CRED_BBS_OK, *jwp_out / *jwp_len_out own a UTF-8 buffer (not
 * NUL-terminated) to be released with zk_cred_bbs_free_buffer. */
int32_t zk_cred_bbs_jwp_issue(uint32_t suite,
                              const uint8_t *secret_key, size_t secret_key_len,
                              const uint8_t *public_key, size_t public_key_len,
                              const uint8_t *commitment_with_proof,
                              size_t commitment_with_proof_len,
                              const uint8_t *vct, size_t vct_len,
                              const uint8_t *issuer_claims_json,
                              size_t issuer_claims_json_len,
                              const uint8_t *holder_pointers_json,
                              size_t holder_pointers_json_len,
                              const uint8_t *extra_header_json,
                              size_t extra_header_json_len,
                              uint32_t keybind,
                              uint8_t **jwp_out, size_t *jwp_len_out,
                              char **error_out);

/* Verifier: check a presentation and report what it disclosed.
 *
 * On ZK_CRED_BBS_OK, *result_out / *result_len_out own a UTF-8 JSON
 * document shaped like
 *   {"vct":"...","disclosed":[{"pointer":"/given_name","value":"Alice"}]}
 * to be released with zk_cred_bbs_free_buffer. "value" is the claim's real
 * JSON value, so a number stays a number.
 *
 * Any verification failure returns ZK_CRED_BBS_ERR with a coarse message -
 * never the offending values. */
int32_t zk_cred_bbs_jwp_verify(uint32_t suite,
                               const uint8_t *presented_jwp,
                               size_t presented_jwp_len,
                               const uint8_t *public_key, size_t public_key_len,
                               uint8_t **result_out, size_t *result_len_out,
                               char **error_out);

/* Issuer (raw algebra): verify the commitment (including each
 * authenticator's proof of possession) and blind-sign it.
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

/* Derive the public key belonging to a secret key - SkToPk,
 * draft-irtf-cfrg-bbs-signatures-08 3.4.2.
 *
 * secret_key is the 32-octet big-endian scalar. On ZK_CRED_BBS_OK,
 * *public_key_out / *public_key_len_out own the 96-octet compressed G2
 * point, to be released with zk_cred_bbs_free_buffer.
 *
 * Intended for checking, once at startup, that a configured key PAIR really
 * is one. Nothing cheaper does that job: matching widths says nothing about
 * whether the halves belong together, and signing with a mismatched pair
 * produces credentials that fail at every relying party reporting only
 * "does not verify". */
int32_t zk_cred_bbs_sk_to_pk(const uint8_t *secret_key, size_t secret_key_len,
                             uint8_t **public_key_out, size_t *public_key_len_out,
                             char **error_out);

/* Release a buffer written to a *_out / *_len_out pair. */
void zk_cred_bbs_free_buffer(uint8_t *ptr, size_t len);

/* Release an error string written to an error_out parameter. NULL-safe. */
void zk_cred_bbs_free_error_string(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ZK_CRED_BBS_GO_H */
