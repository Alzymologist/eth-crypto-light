//! Seed calculation.

#[cfg(any(feature = "std", test))]
use std::string::String;

#[cfg(all(not(feature = "std"), not(test)))]
use alloc::string::String;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::Error;

/// Length of the seed array.
pub const SEED_LEN: usize = 64;

/// Number of `pbkdf2` iterations.
pub const PBKDF2_ITER: u32 = 2048;

/// Calculate seed from secret bytes.
///
/// Note that in ethereum seed calculation the seed phrase itself is used as
/// bytes.
pub fn seed(bytes: &[u8], password: &str) -> Result<[u8; SEED_LEN], Error> {
    let mut salt = String::with_capacity(8 + password.len());
    salt.push_str("mnemonic");
    salt.push_str(password);

    let mut seed = [0u8; SEED_LEN];

    let result = pbkdf2::<Hmac<Sha512>>(bytes, salt.as_bytes(), PBKDF2_ITER, &mut seed);

    salt.zeroize();

    if result.is_ok() {
        Ok(seed)
    } else {
        Err(Error::Pbkdf2Internal)
    }
}
