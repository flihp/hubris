// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API crate for the 'attest' task.

#![no_std]

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

// used as an idol 'Complex' error response
#[derive(
    Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum NullError {
    SomethingBad,
}

// used as an idol 'CLike' error response
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NullErrorZ {
    SomethingBad = 1,
}

impl From<u32> for NullErrorZ {
    fn from(i: u32) -> Self {
        match i {
            1 => Self::SomethingBad,
            _ => panic!("Invalid NullErrorZ"),
        }
    }
}

impl From<NullErrorZ> for u16 {
    fn from(e: NullErrorZ) -> Self {
        match e {
            NullErrorZ::SomethingBad => 1,
        }
    }
}

use userlib::sys_send;
include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));
