// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

//! Octet/integer conversions, `expand_message_xmd`, and multi-scalar
//! helpers shared by the BBS and blind-BBS layers.

use bls12_381_plus::G1Projective;
use bls12_381_plus::Scalar;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// SHA-256 output size, `b_in_bytes` in RFC 9380 §5.3.1.
const B_IN_BYTES: usize = 32;
/// SHA-256 input block size, `s_in_bytes` in RFC 9380 §5.3.1.
const S_IN_BYTES: usize = 64;

/// I2OSP (RFC 8017): big-endian fixed-width encoding of a non-negative integer.
///
/// Only the widths the BBS drafts actually use (1, 2, 8) are ever needed,
/// but this accepts any width that fits.
pub fn i2osp(value: u64, length: usize) -> Vec<u8> {
  let be = value.to_be_bytes();
  if length >= be.len() {
    let mut out = vec![0u8; length - be.len()];
    out.extend_from_slice(&be);
    out
  } else {
    // Narrower than 8 bytes: the caller is asserting the value fits.
    debug_assert!(be[..be.len() - length].iter().all(|b| *b == 0), "i2osp: value does not fit in {length} bytes");
    be[be.len() - length..].to_vec()
  }
}

/// `expand_message_xmd` with SHA-256, per RFC 9380 §5.3.1.
///
/// Implemented here rather than taken from the curve crate because the BBS
/// drafts call it directly for `hash_to_scalar` and seeded random scalars,
/// not only as an internal step of hash-to-curve — and because a
/// hand-checkable implementation of a fully specified 20-line function is
/// worth more than a dependency on another crate's non-public internals.
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>> {
  if dst.len() > 255 {
    return Err(Error::InvalidLength {
      what: "DST",
      expected: 255,
      got: dst.len(),
    });
  }
  if len_in_bytes > 65535 {
    return Err(Error::InvalidLength {
      what: "expand_message_xmd output",
      expected: 65535,
      got: len_in_bytes,
    });
  }
  let ell = len_in_bytes.div_ceil(B_IN_BYTES);
  if ell > 255 {
    return Err(Error::TooMany("expand_message_xmd blocks"));
  }

  let mut dst_prime = dst.to_vec();
  dst_prime.extend_from_slice(&i2osp(dst.len() as u64, 1));

  // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
  let mut h = Sha256::new();
  h.update(vec![0u8; S_IN_BYTES]);
  h.update(msg);
  h.update(i2osp(len_in_bytes as u64, 2));
  h.update(i2osp(0, 1));
  h.update(&dst_prime);
  let b_0: [u8; B_IN_BYTES] = h.finalize().into();

  // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
  let mut h = Sha256::new();
  h.update(b_0);
  h.update(i2osp(1, 1));
  h.update(&dst_prime);
  let mut b_prev: [u8; B_IN_BYTES] = h.finalize().into();

  let mut out = Vec::with_capacity(ell * B_IN_BYTES);
  out.extend_from_slice(&b_prev);

  for i in 2..=ell {
    // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
    let mut xored = [0u8; B_IN_BYTES];
    for j in 0..B_IN_BYTES {
      xored[j] = b_0[j] ^ b_prev[j];
    }
    let mut h = Sha256::new();
    h.update(xored);
    h.update(i2osp(i as u64, 1));
    h.update(&dst_prime);
    b_prev = h.finalize().into();
    out.extend_from_slice(&b_prev);
  }

  out.truncate(len_in_bytes);
  Ok(out)
}

/// `OS2IP(octets) mod r` for the 48-octet uniform strings BBS produces.
///
/// `Scalar::from_okm` performs exactly this reduction, treating its input as
/// a big-endian integer (verified against its implementation, which splits
/// the 48 bytes into two big-endian 192-bit digits and combines them as
/// `d0 * 2^192 + d1`).
pub fn os2ip_48_mod_r(octets: &[u8]) -> Result<Scalar> {
  let bytes: [u8; 48] = octets.try_into().map_err(|_| Error::InvalidLength {
    what: "uniform bytes",
    expected: 48,
    got: octets.len(),
  })?;
  Ok(Scalar::from_okm(&bytes))
}

/// Multi-scalar multiplication: `sum(points[i] * scalars[i])`.
pub fn sumprod(points: &[G1Projective], scalars: &[Scalar]) -> Result<G1Projective> {
  if points.len() != scalars.len() {
    return Err(Error::MismatchedLengths {
      what: "points and scalars",
      a: points.len(),
      b: scalars.len(),
    });
  }
  Ok(points.iter().zip(scalars.iter()).fold(G1Projective::IDENTITY, |acc, (p, s)| acc + p * s))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn i2osp_widths() {
    assert_eq!(i2osp(0, 1), vec![0]);
    assert_eq!(i2osp(1, 1), vec![1]);
    assert_eq!(i2osp(255, 1), vec![255]);
    assert_eq!(i2osp(256, 2), vec![1, 0]);
    assert_eq!(i2osp(1, 8), vec![0, 0, 0, 0, 0, 0, 0, 1]);
  }

  #[test]
  fn expand_message_xmd_long_output_spans_blocks() {
    let out = expand_message_xmd(b"abc", b"DST", 128).unwrap();
    assert_eq!(out.len(), 128);
    // Blocks must differ; a broken loop that repeats b_1 would not.
    assert_ne!(out[0..32], out[32..64]);
    assert_ne!(out[32..64], out[64..96]);
  }

  #[test]
  fn expand_message_xmd_rejects_oversize() {
    assert!(expand_message_xmd(b"", b"DST", 65536).is_err());
    assert!(expand_message_xmd(b"", &[0u8; 256], 32).is_err());
  }
}
