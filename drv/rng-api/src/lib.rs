// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API crate for the random number generator.

#![no_std]

use core::convert::TryFrom;
use core::num::NonZeroU32;
use rand_core::impls;
pub use rand_core::{Error, RngCore};
use userlib::{sys_send, FromPrimitive};

#[repr(u32)]
#[derive(Copy, Clone, Debug, FromPrimitive)]
pub enum RngError {
    BadArg,
    PoweredOff,
    TimeoutChi2Min,
    TimeoutChi2Gt4,
    TimeoutRefreshCnt,
}

impl From<RngError> for u16 {
    fn from(rc: RngError) -> Self {
        u16::try_from(rc).expect("Overflow converting from RngError to u16.")
    }
}

impl From<RngError> for u32 {
    fn from(rc: RngError) -> Self {
        rc as Self
    }
}

impl From<u32> for RngError {
    fn from(u: u32) -> Self {
        match FromPrimitive::from_u32(u) {
            Some(err) => err,
            None => panic!("Invalid u32 for conversion to RngError."),
        }
    }
}

// This function transforms an RngError to an error code appropriate for
// rng_core by adding Error::CUSTOM_START to its u32 representation:
// https://docs.rs/rand_core/0.6.3/rand_core/struct.Error.html#associatedconstant.CUSTOM_START
impl From<RngError> for Error {
    fn from(e: RngError) -> Self {
        let code = u32::from(e) + Error::CUSTOM_START;
        match NonZeroU32::new(code) {
            Some(rc) => Error::from(rc),
            None => {
                panic!("Invalid RngError for conversion to rand_core::Error.")
            }
        }
    }
}

impl From<Error> for RngError {
    fn from(e: Error) -> Self {
        // in no_std 'code' always returns a NonZeroU32
        // https://docs.rs/rand_core/latest/rand_core/struct.Error.html#method.code
        let code = e.code().unwrap().get();
        if code < Error::CUSTOM_START {
            panic!("Invalid rand_core::Error for conversion to RngError.");
        }
        RngError::from(code - Error::CUSTOM_START)
    }
}

// To use the 'getrandom' and 'rand::rngs::OsRng' this custom 'getrandom'
// function must be registered in the root binary crate.
//
// fn main() {
//     let mut buf: [u8; 32] = [0; 32];
//
//     use getrandom::{getrandom, register_custom_getrandom};
//     use drv_rng_api::rng_getrandom;
//     register_custom_getrandom!(rng_getrandom);
//     if getrandom(buf).is_ok() {
//         // do something
//     }
//
//     use rand_core::{OsRng, RngCore};
//     if OsRng.try_fill_bytes(buf).is_ok() {
//         // do something
//     }
// }
#[cfg(feature = "custom-getrandom")]
pub fn rng_getrandom(dest: &mut [u8]) -> Result<(), Error> {
    task_slot!(RNG, rng_driver);
    let task_id = RNG.get_task_id();
    match Rng::from(task_id).fill(dest) {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::from(err)),
    }
}

// struct Rng is defined in the code generated by the IDL. We implement the
// RngCore trait for this struct to allow callers to use this familiar
// interface directly or to use the Rng in interfaces with traits bound to
// RngCore.
include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));

// fn main() {
//     use drv_rng_api::Rng;
//     use rand::RngCore;
//
//     task_slot!(RNG, rng_driver);
//
//     let mut buf: [u8; 32] = [0; 32];
//     let rng = Rng::from(RNG.get_task_id());
//     if rng.try_fill_bytes(buf).is_ok() {
//         // do something
//     }
// }
impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("RNG failed to fill the provided buffer.")
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        match self.fill(dest) {
            Ok(_) => Ok(()),
            Err(err) => Err(Error::from(err)),
        }
    }
}
