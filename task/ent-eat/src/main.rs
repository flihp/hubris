// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use getrandom::{ getrandom, register_custom_getrandom };
use drv_rng_api::{ rng_fill, rng_getrandom };
use userlib::*;

use ringbuf::*;

register_custom_getrandom!(rng_getrandom);
task_slot!(RNG, rng_driver);

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Init,
    LoopBegin,
    GetRandom,
    RngFill(usize),
    Sleep(u64),
    None,
}

ringbuf!(Trace, 64, Trace::None);

const ERR_SLEEP: u64 = 6666;
#[inline(never)]
fn sleep_for_getrandom(buf: &mut [u8]) {
    ringbuf_entry!(Trace::GetRandom);
    if getrandom(buf).is_ok() {
        for b in buf {
            ringbuf_entry!(Trace::Sleep(*b as u64));
            hl::sleep_for(*b as u64);
        }
    } else {
        ringbuf_entry!(Trace::Sleep(ERR_SLEEP));
        hl::sleep_for(ERR_SLEEP);
    }
    ()
}

#[inline(never)]
fn sleep_for_rng_fill(buf: &mut [u8]) {
    ringbuf_entry!(Trace::RngFill(buf.len()));
    if rng_fill(RNG.get_task_id(), buf).is_ok() {
        for b in buf {
            ringbuf_entry!(Trace::Sleep(*b as u64));
            hl::sleep_for(*b as u64);
        }
    } else {
        ringbuf_entry!(Trace::Sleep(ERR_SLEEP));
        hl::sleep_for(ERR_SLEEP);
    }
    ()
}

#[export_name = "main"]
pub fn main() -> ! {
    let mut buf: [u8; 32] = [0; 32];

    ringbuf_entry!(Trace::Init);
    loop {
        hl::sleep_for(9999);
        ringbuf_entry!(Trace::LoopBegin);
        sleep_for_getrandom(&mut buf);
        sleep_for_rng_fill(&mut buf);
    }
}
