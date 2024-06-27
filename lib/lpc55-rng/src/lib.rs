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
use userlib::hl;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Lpc55RngError {
    TimeoutChi2Min,
    TimeoutChi2Gt4,
}

pub struct Lpc55Rng {
    pub pmc: &'static pmc::RegisterBlock,
    pub rng: &'static rng::RegisterBlock,
}

const INIT_RETRY_MAX: u8 = 5;
const INIT_SLEEP_TICKS: u64 = 200;

#[repr(u8)]
#[allow(dead_code)]
enum ChiClock {
    XorAll = 0b000,
    First = 0b001,
    Second = 0b010,
    Third = 0b011,
    Fourth = 0b100,
    Reserved,
}

impl From<ChiClock> for u8 {
    fn from(val: ChiClock) -> u8 {
        match val {
            ChiClock::XorAll => 0b000,
            ChiClock::First => 0b001,
            ChiClock::Second => 0b010,
            ChiClock::Third => 0b011,
            ChiClock::Fourth => 0b100,
            ChiClock::Reserved => 0b111,
        }
    }
}

#[repr(u8)]
#[allow(dead_code)]
enum CounterMode {
    Disabled = 0b00,
    UpdateOnce = 0b01,
    FreeRunning = 0b10,
    Reserved,
}

impl From<CounterMode> for u8 {
    fn from(val: CounterMode) -> u8 {
        match val {
            CounterMode::Disabled => 0b00,
            CounterMode::UpdateOnce => 0b01,
            CounterMode::FreeRunning => 0b10,
            CounterMode::Reserved => 0b11,
        }
    }
}

impl Default for Lpc55Rng {
    fn default() -> Self {
        Self::new()
    }
}

impl Lpc55Rng {
    pub fn new() -> Self {
        Lpc55Rng {
            pmc: unsafe { &*PMC::ptr() },
            rng: unsafe { &*RNG::ptr() },
        }
    }

    /// Initialize the hardware RNG per UM11126 v2.4 §48.15.5
    pub fn init(&self, syscon: &Syscon) -> Result<(), Lpc55RngError> {
        // Power on & reset per step 1
        self.poweron_reset(syscon);

        // 48.16.3 / Table 1027 lists the default value for the MODE field in
        // the COUNTER_CFG register as `0`. In practice we've found the LPC55
        // sets this field to `2` instead. If we set the MODE field to the
        // default value `0` instead the RNG ... TODO: describe what happens
        self.set_counter_mode(CounterMode::FreeRunning);

        // This defaults to `ChiClock::XorAll` / `0b000` which seems to work.
        // The instructions for using the chi^2 test wants `1b` hardware (the
        // only hardware we support) to set this to `ChiClock::Fourth` /
        // `0b100`:
        // self.set_chi_clock(ChiClock::Fourth);
        //
        // In this configuration we never get out of step 4 though:
        // the contents of the ONLINE_TEST_VAL.MAX_CHI_SQUARED never reaches
        // the required threshold.
        self.set_chi_clock(ChiClock::XorAll);

        // Enable entropy accumulation test per instructions in step 2
        // for Revision 1B hardware (the only we support).
        let mut retry = 0;
        loop {
            self.enable_online_test();
            // Wait for MAX_CHI_SQUARED > MIN_CHI_SQUARED per step 3
            let mut retry_chi_min = 0;
            while self.min_chi_squared() >= self.max_chi_squared() {
                if retry_chi_min < INIT_RETRY_MAX {
                    retry_chi_min += 1;
                    hl::sleep_for(INIT_SLEEP_TICKS);
                } else {
                    return Err(Lpc55RngError::TimeoutChi2Min);
                }
            }

            // This is step 4. Not sure how to describe it / what to call it.
            if self.max_chi_squared() > 4 {
                self.disable_online_test();
                self.shift4x_increment();
                if retry < INIT_RETRY_MAX {
                    hl::sleep_for(INIT_SLEEP_TICKS);
                    retry += 1;
                } else {
                    return Err(Lpc55RngError::TimeoutChi2Gt4);
                }
            } else {
                break Ok(());
            }
        }
    }

    #[inline]
    fn poweron_reset(&self, syscon: &Syscon) {
        self.pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredoff());
        self.pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredon());

        syscon.enable_clock(Peripheral::Rng);
        syscon.enter_reset(Peripheral::Rng);
        syscon.leave_reset(Peripheral::Rng);
    }

    #[inline]
    fn set_counter_mode(&self, mode: CounterMode) {
        self.rng
            .counter_cfg
            .modify(|_, w| unsafe { w.mode().bits(mode.into()) })
    }

    #[inline]
    /// select the clock used in chi^2 computation per UM11126 v2.4 §48.15.5
    /// step 2
    // manual states that Revision 1B hardware should use clock 4
    fn set_chi_clock(&self, chi_clock: ChiClock) {
        // SAFETY: This is unsafe because the PAC crate doesn't
        // guarantee that we're setting this field to an valid value.
        // According to LPC55 UM11126 v2.4 §48.16.3 table 1027 defines
        // valid values for this field as 0-4. This function sets the field
        // to 4 which is valid.
        self.rng
            .counter_cfg
            .modify(|_, w| unsafe { w.clock_sel().bits(chi_clock.into()) })
    }

    #[inline]
    /// Disable online RNG / chi^2 test
    fn disable_online_test(&self) {
        self.rng
            .online_test_cfg
            .modify(|_, w| w.activate().clear_bit())
    }

    #[inline]
    /// Enable online RNG / chi^2 test
    fn enable_online_test(&self) {
        self.rng
            .online_test_cfg
            .modify(|_, w| w.activate().set_bit())
    }

    #[inline]
    fn min_chi_squared(&self) -> u8 {
        self.rng.online_test_val.read().min_chi_squared().bits()
    }

    #[inline]
    fn max_chi_squared(&self) -> u8 {
        self.rng.online_test_val.read().max_chi_squared().bits()
    }

    #[inline]
    fn shift4x_increment(&self) {
        if self.rng.counter_cfg.read().shift4x().bits() < 7 {
            // SAFETY: This is unsafe because the PAC crate doesn't
            // guarantee that we're setting this field to an valid value.
            // According to LPC55 UM11126 v2.4 §48.16.3 table 1027 defines
            // valid values for this field as 0-7. We test for this in the
            // conditional above.
            self.rng.counter_cfg.modify(|r, w| unsafe {
                w.shift4x().bits(r.shift4x().bits() + 1)
            });
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
