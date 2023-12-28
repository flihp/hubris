// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API crate for the 'attest' task.

#![no_std]

#[derive(
    Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum NullError {
    SomethingBad,
    LeasesNotEqual,
    LeaseTooBig,
}

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use userlib::sys_send;

include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));
