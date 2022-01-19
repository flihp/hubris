// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Driver for the LPC55 random number generator.
//!
//! Use the rng-api crate to interact with this driver.

#![no_std]
#![no_main]

use core::mem::size_of;
use drv_lpc55_syscon_api::{Peripheral, Syscon};
use drv_rng_api::RngError;
use idol_runtime::{ClientError, RequestError};
use rand_core::{impls, Error, RngCore};
use userlib::*;

use lpc55_pac as device;

task_slot!(SYSCON, syscon_driver);

struct Lpc55Rng {
    rng: &'static lpc55_pac::rng::RegisterBlock,
}

impl Lpc55Rng {
    fn new() -> Self {
        Lpc55Rng {
            rng: unsafe { &*device::RNG::ptr() },
        }
    }
}

impl RngCore for Lpc55Rng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("Failed to get entropy from RNG.")
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let mut cnt = 0;
        let len = dest.len();
        const STEP: usize = size_of::<u32>();
        // fill in multiples of STEP / RNG register size
        for _ in 0..(len / STEP) {
            let ent = self.rng.random_number.read().bits();
            dest[cnt..cnt + STEP].clone_from_slice(&ent.to_ne_bytes());
            cnt += STEP;
        }
        // fill in remaining
        let remain = len - cnt;
        assert!(remain < STEP);
        if remain > 0 {
            let ent = self.rng.random_number.read().bits();
            dest[len - remain..].clone_from_slice(&ent.to_ne_bytes());
        }
        Ok(())
    }
}

impl idl::InOrderRngImpl for Lpc55Rng {
    fn fill(
        &mut self,
        _: &userlib::RecvMessage,
        dest: idol_runtime::Leased<idol_runtime::W, [u8]>,
    ) -> Result<usize, RequestError<RngError>> {
        let mut cnt = 0;
        const STEP: usize = size_of::<u32>();
        let mut buf = [0u8; STEP];
        // fill in multiples of STEP / RNG register size
        for _ in 0..(dest.len() / STEP) {
            self.try_fill_bytes(&mut buf)
                .map_err(|e| RngError::from(e))?;
            dest.write_range(cnt..cnt + STEP, &buf)
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += STEP;
        }
        // fill in remaining
        let remain = dest.len() - cnt;
        assert!(remain < STEP);
        if remain > 0 {
            self.try_fill_bytes(&mut buf)
                .map_err(|e| RngError::from(e))?;
            dest.write_range(dest.len() - remain..dest.len(), &buf)
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += remain;
        }
        Ok(cnt)
    }
}

#[export_name = "main"]
fn main() -> ! {
    let syscon = SYSCON.get_task_id();
    let syscon = Syscon::from(syscon);

    syscon.enable_clock(Peripheral::Rng);

    let pmc = unsafe { &*device::PMC::ptr() };

    pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredon());

    let rng = Lpc55Rng::new();
    let reseed_threshold = 0x100000; // 1 MiB
    let mut rng = Lpc55RngServer::new(rng, reseed_threshold)
        .expect("Failed to create RngServer");

    let mut buffer = [0u8; idl::INCOMING_SIZE];

    loop {
        idol_runtime::dispatch(&mut buffer, &mut rng);
    }
}

mod idl {
    use drv_rng_api::RngError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
