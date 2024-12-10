#![no_std]
#![deny(unused_crate_dependencies)]

#[cfg(any(feature = "std", test))]
#[macro_use]
extern crate std;

#[cfg(all(not(feature = "std"), not(test)))]
#[macro_use]
extern crate alloc;

pub mod derive;
pub mod error;
pub mod seed;
pub mod signer;
