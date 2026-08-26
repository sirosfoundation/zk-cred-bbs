// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Plain C-ABI bindings for Go (cgo) — the `zk-cred-bbs` counterpart of
//! `zk-cred-longfellow`'s and `zk-cred-vega`'s own `src/go_ffi.rs` (mirror
//! those files' shape/conventions if this one needs to change).
//!
//! `ffi_api.rs` exports a UniFFI ABI for the native wallet SDKs, behind the
//! `uniffi` feature. UniFFI does not target Go and its RustBuffer protocol
//! is not cgo-friendly, so this module is a separate, hand-written,
//! ordinary `extern "C"` ABI, built unconditionally.
//!
//! ## What Go needs, and what it does not
//!
//! Unlike the other two crates, `vc` needs this on **both** sides:
//!
//! * the **issuer** calls [`zk_cred_bbs_blind_sign`], which verifies the
//!   holder's commitment (including the authenticator's proof of
//!   possession) and then blind-signs it;
//! * the **verifier** calls [`zk_cred_bbs_blind_proof_verify`].
//!
//! Nothing on the holder's side is exposed here — no Go service ever
//! commits or proves.
//!
//! ## No handles
//!
//! BBS has no proving key to load and no circuit to compile, so unlike
//! Longfellow's `MdocZkVerifier` or Vega's `GoVegaVerifierKey` there is no
//! opaque handle to create, cache, or free. Every call is bytes in, bytes
//! out. The only caller-owned allocations are the error string and the
//! signature buffer, each with its own free function.
//!
//! ## Error reporting
//!
//! Same "owned, caller-freed error string" shape as the sibling crates:
//! every fallible function takes an `error_out: *mut *mut c_char`
//! out-parameter (may be null). On failure an owned NUL-terminated UTF-8
//! error string is written there, to be freed via
//! [`zk_cred_bbs_free_error_string`]. On success `*error_out` is set to
//! null (if non-null).
//!
//! ## Panics
//!
//! Every exported function wraps its body in `catch_unwind` and reports a
//! panic as an ordinary error. A panic unwinding across the FFI boundary
//! would be undefined behaviour and would take the Go process with it.

use crate::blind::{BlindSuite, Disclosure, PLAIN_SUITE_ID, SCHNORR_SUITE_ID};
use crate::error::Error;
use crate::keybind::SchnorrBls12381;
use crate::suite::{ScalarSource, Suite};
use std::ffi::{CString, c_char};
use std::slice;

/// Status: the operation succeeded.
pub const ZK_CRED_BBS_OK: i32 = 0;
/// Status: the operation failed; see the error out-parameter.
pub const ZK_CRED_BBS_ERR: i32 = -1;
/// Status: a panic was caught crossing the FFI boundary.
pub const ZK_CRED_BBS_PANIC: i32 = -2;

/// Suite selector, matching `BbsSuiteId` in `ffi_api.rs`.
pub const ZK_CRED_BBS_SUITE_PLAIN: u32 = 0;
/// Suite selector for the Schnorr key binding profile.
pub const ZK_CRED_BBS_SUITE_SCHNORR: u32 = 1;

/// Disclosure codes, matching `BbsDisclosure` in `ffi_api.rs`.
pub const ZK_CRED_BBS_DISCLOSE: u8 = 0;
/// Prove knowledge without revealing.
pub const ZK_CRED_BBS_HIDE: u8 = 1;
/// Hide, and emit a Pedersen commitment.
pub const ZK_CRED_BBS_COMMIT: u8 = 2;

// The C header is hand-maintained. These assertions tie it to the Rust
// constants so a change here fails the build rather than silently
// desyncing the two — the same guard `zk-cred-vega` uses for its own
// hand-written header.
const _: () = assert!(ZK_CRED_BBS_OK == 0, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_ERR == -1, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_PANIC == -2, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_SUITE_PLAIN == 0, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_SUITE_SCHNORR == 1, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_DISCLOSE == 0, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_HIDE == 1, "zk_cred_bbs_go.h must be updated to match");
const _: () = assert!(ZK_CRED_BBS_COMMIT == 2, "zk_cred_bbs_go.h must be updated to match");

/// Formats a `catch_unwind` payload into a human-readable message.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
  if let Some(s) = payload.downcast_ref::<&str>() {
    format!("panic in FFI call: {s}")
  } else if let Some(s) = payload.downcast_ref::<String>() {
    format!("panic in FFI call: {s}")
  } else {
    "panic in FFI call: unknown panic payload".to_owned()
  }
}

/// Writes an owned error string to `error_out`, if it is non-null.
///
/// # Safety
///
/// `error_out` may be null; if non-null it must point to a valid, writable
/// `*mut c_char`.
unsafe fn set_error_out(error_out: *mut *mut c_char, message: &str) {
  if error_out.is_null() {
    return;
  }
  // A NUL byte inside the message would truncate it; replace rather than
  // fail, since this is already the error path.
  let cstring = CString::new(message.replace('\0', "?")).unwrap_or_else(|_| CString::new("error message could not be encoded").expect("literal has no NUL"));
  unsafe { *error_out = cstring.into_raw() };
}

/// Clears `*error_out` on the success path.
///
/// # Safety
///
/// As [`set_error_out`].
unsafe fn clear_error_out(error_out: *mut *mut c_char) {
  if !error_out.is_null() {
    unsafe { *error_out = std::ptr::null_mut() };
  }
}

/// # Safety
///
/// `ptr` must point to at least `len` valid, initialized bytes, or be null
/// when `len` is zero.
unsafe fn bytes_or_empty<'a>(ptr: *const u8, len: usize, what: &str) -> Result<&'a [u8], Error> {
  if len == 0 {
    return Ok(&[]);
  }
  if ptr.is_null() {
    return Err(Error::SignerFailed(format!("{what} pointer is null with non-zero length")));
  }
  Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Reads a `const uint8_t* const*` + lengths array into owned byte vectors.
///
/// # Safety
///
/// `ptrs` and `lens` must each point to `count` valid elements, and each
/// `ptrs[i]` must point to `lens[i]` valid bytes.
unsafe fn read_byte_array(ptrs: *const *const u8, lens: *const usize, count: usize, what: &str) -> Result<Vec<Vec<u8>>, Error> {
  if count == 0 {
    return Ok(Vec::new());
  }
  if ptrs.is_null() || lens.is_null() {
    return Err(Error::SignerFailed(format!("{what} array is null with non-zero count")));
  }
  let ptrs = unsafe { slice::from_raw_parts(ptrs, count) };
  let lens = unsafe { slice::from_raw_parts(lens, count) };
  let mut out = Vec::with_capacity(count);
  for i in 0..count {
    out.push(unsafe { bytes_or_empty(ptrs[i], lens[i], what) }?.to_vec());
  }
  Ok(out)
}

fn suite_for(selector: u32) -> Result<BlindSuite<SchnorrBls12381>, Error> {
  let id = match selector {
    ZK_CRED_BBS_SUITE_PLAIN => PLAIN_SUITE_ID,
    ZK_CRED_BBS_SUITE_SCHNORR => SCHNORR_SUITE_ID,
    _ => return Err(Error::Unsupported("unknown suite selector")),
  };
  Ok(BlindSuite::new(Suite::new(ScalarSource::System), SchnorrBls12381, id))
}

fn disclosures_from_codes(codes: &[u8]) -> Result<Vec<Disclosure>, Error> {
  codes
    .iter()
    .map(|c| match *c {
      ZK_CRED_BBS_DISCLOSE => Ok(Disclosure::Disclose),
      ZK_CRED_BBS_HIDE => Ok(Disclosure::Hide),
      ZK_CRED_BBS_COMMIT => Ok(Disclosure::Commit),
      _ => Err(Error::Unsupported("unknown disclosure code")),
    })
    .collect()
}

/// Verify a holder's commitment and blind-sign it — the issuer's entry
/// point.
///
/// On success writes an owned buffer to `signature_out`/`signature_len_out`,
/// to be released with [`zk_cred_bbs_free_buffer`], and returns
/// [`ZK_CRED_BBS_OK`].
///
/// The commitment's embedded proof, including each authenticator's proof of
/// possession of its key binding key, is verified before signing. A
/// commitment that does not check out is rejected rather than signed.
///
/// # Safety
///
/// * Every pointer/length pair must describe valid, initialized memory.
/// * `messages_ptrs`/`messages_lens` must each have `messages_count`
///   elements.
/// * `signature_out` and `signature_len_out` must be non-null and writable.
/// * `error_out` may be null; see the module documentation.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn zk_cred_bbs_blind_sign(
  suite: u32,
  secret_key: *const u8,
  secret_key_len: usize,
  public_key: *const u8,
  public_key_len: usize,
  commitment_with_proof: *const u8,
  commitment_with_proof_len: usize,
  header: *const u8,
  header_len: usize,
  messages_ptrs: *const *const u8,
  messages_lens: *const usize,
  messages_count: usize,
  signature_out: *mut *mut u8,
  signature_len_out: *mut usize,
  error_out: *mut *mut c_char,
) -> i32 {
  let result = std::panic::catch_unwind(|| -> Result<Vec<u8>, Error> {
    // SAFETY: pointer validity is part of this function's safety contract.
    let sk_bytes = unsafe { bytes_or_empty(secret_key, secret_key_len, "secret_key") }?;
    let pk = unsafe { bytes_or_empty(public_key, public_key_len, "public_key") }?;
    let commitment = unsafe { bytes_or_empty(commitment_with_proof, commitment_with_proof_len, "commitment_with_proof") }?;
    let header = unsafe { bytes_or_empty(header, header_len, "header") }?;
    let messages = unsafe { read_byte_array(messages_ptrs, messages_lens, messages_count, "messages") }?;

    let sk = crate::bbs::scalar_from_be(sk_bytes)?;
    suite_for(suite)?.blind_sign(&sk, pk, commitment, header, &messages)
  });

  match result {
    Ok(Ok(signature)) => {
      if signature_out.is_null() || signature_len_out.is_null() {
        // SAFETY: as above.
        unsafe { set_error_out(error_out, "signature out-parameters must not be null") };
        return ZK_CRED_BBS_ERR;
      }
      let mut boxed = signature.into_boxed_slice();
      let ptr = boxed.as_mut_ptr();
      let len = boxed.len();
      std::mem::forget(boxed);
      // SAFETY: as above.
      unsafe {
        *signature_out = ptr;
        *signature_len_out = len;
        clear_error_out(error_out);
      }
      ZK_CRED_BBS_OK
    }
    Ok(Err(e)) => {
      // SAFETY: as above.
      unsafe { set_error_out(error_out, &e.to_string()) };
      ZK_CRED_BBS_ERR
    }
    Err(panic) => {
      // SAFETY: as above.
      unsafe { set_error_out(error_out, &panic_message(&*panic)) };
      ZK_CRED_BBS_PANIC
    }
  }
}

/// Verify a presentation — the relying party's entry point.
///
/// Returns [`ZK_CRED_BBS_OK`] only if the proof is valid for exactly these
/// disclosed messages, disclosure pattern, headers and issuer key. Any
/// failure returns [`ZK_CRED_BBS_ERR`] with a message in `error_out`; the
/// message is a coarse discriminator, never the offending values.
///
/// # Safety
///
/// As [`zk_cred_bbs_blind_sign`]; additionally `disclosures_ptr` must point
/// to `disclosures_len` valid bytes, each one of the
/// `ZK_CRED_BBS_DISCLOSE`/`HIDE`/`COMMIT` codes.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn zk_cred_bbs_blind_proof_verify(
  suite: u32,
  public_key: *const u8,
  public_key_len: usize,
  proof: *const u8,
  proof_len: usize,
  header: *const u8,
  header_len: usize,
  presentation_header: *const u8,
  presentation_header_len: usize,
  issuer_known_messages_no: usize,
  disclosed_ptrs: *const *const u8,
  disclosed_lens: *const usize,
  disclosed_count: usize,
  disclosures_ptr: *const u8,
  disclosures_len: usize,
  error_out: *mut *mut c_char,
) -> i32 {
  let result = std::panic::catch_unwind(|| -> Result<(), Error> {
    // SAFETY: pointer validity is part of this function's safety contract.
    let pk = unsafe { bytes_or_empty(public_key, public_key_len, "public_key") }?;
    let proof = unsafe { bytes_or_empty(proof, proof_len, "proof") }?;
    let header = unsafe { bytes_or_empty(header, header_len, "header") }?;
    let ph = unsafe { bytes_or_empty(presentation_header, presentation_header_len, "presentation_header") }?;
    let disclosed = unsafe { read_byte_array(disclosed_ptrs, disclosed_lens, disclosed_count, "disclosed_messages") }?;
    let codes = unsafe { bytes_or_empty(disclosures_ptr, disclosures_len, "disclosures") }?;
    let disclosures = disclosures_from_codes(codes)?;

    suite_for(suite)?.blind_proof_verify(pk, proof, header, ph, issuer_known_messages_no, &disclosed, &disclosures)
  });

  match result {
    Ok(Ok(())) => {
      // SAFETY: as above.
      unsafe { clear_error_out(error_out) };
      ZK_CRED_BBS_OK
    }
    Ok(Err(e)) => {
      // SAFETY: as above.
      unsafe { set_error_out(error_out, &e.to_string()) };
      ZK_CRED_BBS_ERR
    }
    Err(panic) => {
      // SAFETY: as above.
      unsafe { set_error_out(error_out, &panic_message(&*panic)) };
      ZK_CRED_BBS_PANIC
    }
  }
}

/// Releases a buffer returned by this module.
///
/// # Safety
///
/// `ptr`/`len` must be exactly what a successful call wrote to its
/// `*_out`/`*_len_out` pair, and must be freed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_bbs_free_buffer(ptr: *mut u8, len: usize) {
  if ptr.is_null() || len == 0 {
    return;
  }
  // SAFETY: reconstructs exactly the Box<[u8]> that was leaked above.
  unsafe {
    drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
  }
}

/// Releases an error string written to an `error_out` parameter.
///
/// # Safety
///
/// `s` must be a pointer this module wrote to an `error_out`, freed at most
/// once. Null is accepted and ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_bbs_free_error_string(s: *mut c_char) {
  if s.is_null() {
    return;
  }
  // SAFETY: reconstructs exactly the CString that was leaked above.
  unsafe {
    drop(CString::from_raw(s));
  }
}
