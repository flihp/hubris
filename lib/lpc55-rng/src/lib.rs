// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use core::{cmp, mem};
use drv_lpc55_syscon_api::{Peripheral, Syscon};
use drv_rng_api::RngError;
use lpc55_pac::{pmc, rng, PMC, RNG};
use rand_core::{impls, Error, RngCore};

pub struct Lpc55Rng {
    pub pmc: &'static pmc::RegisterBlock,
    pub rng: &'static rng::RegisterBlock,
}

impl Lpc55Rng {
    pub fn new(syscon: &Syscon) -> Self {
        let pmc = unsafe { &*PMC::ptr() };
        pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredon());

        syscon.enable_clock(Peripheral::Rng);
        syscon.enter_reset(Peripheral::Rng);
        syscon.leave_reset(Peripheral::Rng);

        Lpc55Rng {
            pmc,
            rng: unsafe { &*RNG::ptr() },
        }
    }
}

impl RngCore for Lpc55Rng {
    /// Get the next 4 bytes from the HRNG.
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    /// Get the next 8 bytes from the HRNG.
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    /// Fill the provided buffer with output from the HRNG.
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).expect("fill_bytes")
    }

    /// Fill the provided buffer with output from the HRNG. If the HRNG
    /// can't service the request an error is returned.
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Error> {
        let mut filled = 0;
        while filled < dst.len() {
            if self.pmc.pdruncfg0.read().pden_rng().bits() {
                return Err(RngError::PoweredOff.into());
            }

            let src = self.rng.random_number.read().bits();
            let len = cmp::min(mem::size_of_val(&src), dst[filled..].len());

            dst[filled..filled + len]
                .copy_from_slice(&src.to_le_bytes()[..len]);
            filled += len;
        }

        Ok(())
    }
}
