// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
//! Blind BBS signatures with hardware key binding.
//!
//! See `README.md` for an overview and `PROFILE.md` for the exact
//! construction, its provenance, and its four deliberate deviations from
//! the CFRG draft.

pub mod bbs;
pub mod blind;
pub mod error;
pub mod keybind;
pub mod suite;
pub mod util;

pub use error::{Error, Result};
pub use suite::{ScalarSource, Suite};
