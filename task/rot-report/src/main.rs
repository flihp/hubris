// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use dice::{AliasHandoff, SeedBuf};
use ringbuf::{ringbuf, ringbuf_entry};
use salty::signature::Keypair;
use userlib::hl;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Trace {
    DeviceIdCertSize(usize),
    AliasCertSize(usize),
    SleepFor(u64),
    None,
}

ringbuf!(Trace, 64, Trace::None);

#[export_name = "main"]
fn main() -> ! {
    loop {
        let ticks = 1000u64;
        ringbuf_entry!(Trace::SleepFor(ticks));
        hl::sleep_for(ticks);

        let alias_handoff = AliasHandoff::from_mem();
        ringbuf_entry!(Trace::DeviceIdCertSize(
            alias_handoff.deviceid_cert.len()
        ));
        ringbuf_entry!(Trace::AliasCertSize(alias_handoff.alias_cert.len()));

        let _alias_keypair = Keypair::from(alias_handoff.seed.as_bytes());
    }
}
