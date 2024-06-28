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
    CheckEnableTimeout,
    CheckTuneTimeout,
    NoEntropy,
    PoweredOff,
    TestFail,
}

// This transform is a 1-way street and we lose information mapping from
// the two possible errors that the Lpc55Rng can produce when insufficient
// entropy is available.
impl From<Lpc55RngError> for RngError {
    fn from(e: Lpc55RngError) -> RngError {
        match e {
            Lpc55RngError::NoEntropy | Lpc55RngError::TestFail => {
                RngError::NoEntropy
            }
            Lpc55RngError::PoweredOff => RngError::PoweredOff,
            _ => RngError::UnknownRngError,
        }
    }
}

pub struct Lpc55Rng {
    pub pmc: &'static pmc::RegisterBlock,
    pub rng: &'static rng::RegisterBlock,
}

const INIT_RETRY_MAX: u8 = 5;
const INIT_SLEEP_TICKS: u64 = 200;

const CHECK_RETRY_MAX: u8 = 5;
const CHECK_SLEEP_TICKS: u64 = 500;

/// UM11126 §48.16.3 / table 1027: bits 2 through 4 in the `COUNTER_CFG`
/// register control the clock used to compute the online test for the HRNG.
#[repr(u8)]
#[allow(dead_code)]
enum CounterClock {
    XorAll = 0b000,
    First = 0b001,
    Second = 0b010,
    Third = 0b011,
    Fourth = 0b100,
    Reserved,
}

impl From<CounterClock> for u8 {
    fn from(val: CounterClock) -> u8 {
        match val {
            CounterClock::XorAll => 0b000,
            CounterClock::First => 0b001,
            CounterClock::Second => 0b010,
            CounterClock::Third => 0b011,
            CounterClock::Fourth => 0b100,
            CounterClock::Reserved => 0b111,
        }
    }
}

/// UM11126 §48.16.3 / table 1027: bits 0 through 1 in the `COUNTER_CFG`
/// register control the mode of operation for the HRNG online test.
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
        // sets this field to `2` instead. If the MODE field is set to the
        // documented default initialization will fail and so we set it
        // explicitly:
        self.set_counter_mode(CounterMode::FreeRunning);

        // This defaults to `CounterClock::XorAll` / `0b000` which seems to work.
        // The instructions for using the online test wants `1b` hardware (the
        // only hardware we support) to set this to `CounterClock::Fourth` /
        // `0b100`:
        // self.set_counter_clock(CounterClock::Fourth);
        //
        // In this configuration we never get out of step 4 though:
        // the contents of the ONLINE_TEST_VAL.MAX_CHI_SQUARED never reaches
        // the required threshold.
        self.set_counter_clock(CounterClock::XorAll);

        let mut retry = 0;
        loop {
            // Enable entropy accumulation test per instructions in step 2
            self.enable_online_test();

            // Wait for MAX_CHI_SQUARED > MIN_CHI_SQUARED per step 3
            // NOTE: we retry this check independent of the outer loop
            let mut retry_min_max = 0;
            while self.min_chi_squared() >= self.max_chi_squared() {
                if retry_min_max < INIT_RETRY_MAX {
                    retry_min_max += 1;
                    hl::sleep_for(INIT_SLEEP_TICKS);
                } else {
                    return Err(Lpc55RngError::CheckEnableTimeout);
                }
            }

            // Step 4 requires that if `max_chi_squared` is > 4 we disable
            // the test, tune the shift4x value by incrementing it, then
            // attempt to initialize the HRNG again.
            if self.max_chi_squared() > 4 {
                self.disable_online_test();
                self.shift4x_increment();
                if retry < INIT_RETRY_MAX {
                    hl::sleep_for(INIT_SLEEP_TICKS);
                    retry += 1;
                } else {
                    return Err(Lpc55RngError::CheckTuneTimeout);
                }
            } else {
                break Ok(());
            }
        }
    }

    /// Read 4 bytes from the hardware RNG per UM11126 v2.4 §48.15.6
    pub fn read(&self) -> Result<u32, Lpc55RngError> {
        if self.pmc.pdruncfg0.read().pden_rng().is_poweredoff() {
            return Err(Lpc55RngError::PoweredOff);
        }

        // Step 1 reminds us to not disable the clock for the online test.
        // Wait for COUNTER_VAL.REFRESH_CNT to become 31 per step 2.
        let mut retry = 0;
        while self.refresh_count() != 31 {
            if retry < CHECK_RETRY_MAX {
                hl::sleep_for(CHECK_SLEEP_TICKS);
                retry += 1;
            } else {
                return Err(Lpc55RngError::NoEntropy);
            }
        }
        // Read RANDOM_NUMBER register to get 4 bytes from HRNG per step 3.
        // This will reset COUNTER_VAL.REFRESH_CNT to zero.
        let out = self.rng.random_number.read().bits();

        // Wait till ONLINE_TEST_VAL.MAX_CHI_SQUARED becomes smaller or equal
        // than 4 per step 4.
        // NOTE: We've already read the output from the RNG, not sure why
        // we're waiting for this when we could just check it first next time
        // around? Move this between step 1 & 2 above?
        retry = 0;
        while self.max_chi_squared() > 4 {
            if retry < CHECK_RETRY_MAX {
                hl::sleep_for(CHECK_SLEEP_TICKS);
                retry += 1;
            } else {
                return Err(Lpc55RngError::TestFail);
            }
        }

        Ok(out)
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
    /// select the clock used in online RNG test per UM11126 v2.4 §48.15.5
    /// step 2
    fn set_counter_clock(&self, counter_clock: CounterClock) {
        // SAFETY: This is unsafe because the PAC crate doesn't
        // guarantee that we're setting this field to an valid value.
        // According to LPC55 UM11126 v2.4 §48.16.3 table 1027 defines
        // valid values for this field as 0-4. The CounterClock type
        // guarantees its conversion to u8 will produce a valid value.
        self.rng
            .counter_cfg
            .modify(|_, w| unsafe { w.clock_sel().bits(counter_clock.into()) })
    }

    #[inline]
    /// Disable online RNG test
    fn disable_online_test(&self) {
        self.rng
            .online_test_cfg
            .modify(|_, w| w.activate().clear_bit())
    }

    #[inline]
    /// Enable online RNG test
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

    #[inline]
    fn refresh_count(&self) -> u8 {
        self.rng.counter_val.read().refresh_cnt().bits()
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
            let src = self.read().map_err(RngError::from)?;
            let len = cmp::min(mem::size_of_val(&src), dst[filled..].len());

            dst[filled..filled + len]
                .copy_from_slice(&src.to_le_bytes()[..len]);
            filled += len;
        }

        Ok(())
    }
}
