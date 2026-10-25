#![forbid(unsafe_code)]
#![forbid(clippy::exit)]

#![deny(clippy::pattern_type_mismatch)]

#![warn(
    clippy::future_not_send,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::must_use_unit,
    clippy::missing_inline_in_public_items,
    clippy::must_use_candidate,
)]

//! # Veritas WebAuthn
//!
//! Veritas WebAuthn is a library for authenticating users with WebAuthn.

extern crate core;

pub mod errors;
pub mod webauthn;
pub mod utils;
pub mod types;
pub mod registration;
pub mod authentication;