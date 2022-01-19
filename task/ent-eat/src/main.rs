// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use drv_rng_api::{rng_getrandom, Rng};
use getrandom::{getrandom, register_custom_getrandom};
use rand_core::{OsRng, RngCore};
use userlib::*;

register_custom_getrandom!(rng_getrandom);
task_slot!(RNG, rng_driver);

const ERR_SLEEP: u64 = 6666;
fn sleep_for_getrandom(buf: &mut [u8]) {
    if getrandom(buf).is_ok() {
        for b in buf {
            hl::sleep_for(*b as u64);
        }
    } else {
        hl::sleep_for(ERR_SLEEP);
    }
    ()
}

fn sleep_for_rng_fill(buf: &mut [u8]) {
    let mut rng = Rng::from(RNG.get_task_id());
    if rng.try_fill_bytes(buf).is_ok() {
        for b in buf {
            hl::sleep_for(*b as u64);
        }
    } else {
        hl::sleep_for(ERR_SLEEP);
    }
    ()
}

fn sleep_for_os_rng(buf: &mut [u8]) {
    if OsRng.try_fill_bytes(buf).is_ok() {
        for b in buf {
            hl::sleep_for(*b as u64);
        }
    } else {
        hl::sleep_for(ERR_SLEEP);
    }
    ()
}

#[export_name = "main"]
pub fn main() -> ! {
    let mut buf: [u8; 32] = [0; 32];

    // ~5 led blinks
    hl::sleep_for(5555);
    loop {
        sleep_for_getrandom(&mut buf);
        sleep_for_rng_fill(&mut buf);
        sleep_for_os_rng(&mut buf);
    }
}
