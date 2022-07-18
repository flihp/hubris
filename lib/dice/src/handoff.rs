// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    cert::{AliasCert, DeviceIdCert},
    AliasOkm, RngSeed, SerialNumber,
};
use hubpack::SerializedSize;
use lpc55_pac::syscon::RegisterBlock;
use serde::{Deserialize, Serialize};

// Currently this memory is the USB peripheral SRAM.
// Do not exceed 0x3fff bytes.
const MEM_START: usize = 0x4010_0000;

// layout of artifacts in handoff memory
const ALIAS_START: usize = MEM_START;
const RNG_START: usize = ALIAS_START + 0x800;

pub struct Handoff<'a>(&'a RegisterBlock);

impl<'a> Handoff<'a> {
    pub fn turn_on(syscon: &'a RegisterBlock) -> Self {
        // handoff through USB SRAM requires we power it on
        syscon.ahbclkctrl2.modify(|_, w| w.usb1_ram().enable());
        syscon
            .presetctrl2
            .modify(|_, w| w.usb1_ram_rst().released());

        Self(syscon)
    }

    pub fn turn_off(self) {
        self.0
            .presetctrl2
            .modify(|_, w| w.usb1_ram_rst().asserted());
        self.0.ahbclkctrl2.modify(|_, w| w.usb1_ram().disable());
    }

    pub fn alias(&self, alias_handoff: &AliasHandoff) -> usize {
        let dst_ptr = ALIAS_START as *mut [u8; AliasHandoff::MAX_SIZE];
        let dst: &mut [u8] = unsafe { &mut *dst_ptr };

        // TODO: error handling
        hubpack::serialize(dst, alias_handoff).expect("serialize rng-handoff")
    }

    pub fn rng(&self, rng_handoff: &RngHandoff) -> usize {
        let dst_ptr = RNG_START as *mut [u8; RngHandoff::MAX_SIZE];
        let dst: &mut [u8] = unsafe { &mut *dst_ptr };

        // TODO: error handling
        hubpack::serialize(dst, rng_handoff).expect("serialize rng-handoff")
    }
}

// Type to access the memory region use to hand DICE derived artifacts off
// to the rot-r.
// TODO: This is specific to self signed DeviceId cert.
#[derive(Deserialize, Serialize, SerializedSize)]
pub struct AliasHandoff {
    pub seed: AliasOkm,
    pub alias_cert: AliasCert,
    pub deviceid_cert: DeviceIdCert,
}

impl AliasHandoff {
    pub fn from_mem() -> Self {
        let src_ptr = ALIAS_START as *const [u8; AliasHandoff::MAX_SIZE];
        let src: &[u8] = unsafe { &*src_ptr };

        let (msg, _) = hubpack::deserialize::<Self>(src).expect("deserialize");

        msg
    }
}

// Type to access the memory region use to hand DICE derived artifacts off
// to the RNG. This will probably only be used by the LPC55 RNG:
// https://rfd.shared.oxide.computer/rfd/0277
#[derive(Deserialize, Serialize, SerializedSize)]
pub struct RngHandoff {
    pub serial_number: SerialNumber,
    pub seed: RngSeed,
}

impl RngHandoff {
    pub fn from_mem() -> Self {
        let src_ptr = RNG_START as *const [u8; RngHandoff::MAX_SIZE];
        let src: &[u8] = unsafe { &*src_ptr };

        let (msg, _) = hubpack::deserialize::<Self>(src).expect("deserialize");

        msg
    }
}
