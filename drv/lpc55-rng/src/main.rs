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
use rand_chacha::ChaCha20Rng;
use rand_core::{impls, Error, RngCore, SeedableRng};
use userlib::*;

use lpc55_pac as device;

task_slot!(SYSCON, syscon_driver);

struct Lpc55Rng {
    pmc: &'static lpc55_pac::pmc::RegisterBlock,
    rng: &'static lpc55_pac::rng::RegisterBlock,
    syscon: Syscon,
}

const RETRY_MAX: u8 = 5;
impl Lpc55Rng {
    fn new() -> Self {
        Lpc55Rng {
            pmc: unsafe { &*device::PMC::ptr() },
            rng: unsafe { &*device::RNG::ptr() },
            syscon: Syscon::from(SYSCON.get_task_id()),
        }
    }

    // Initialization per user manual v2.4, section 48.15.5, 2021-10-08
    fn init(&self) -> Result<(), RngError> {
        // Enable RNG input clock by clearing power down bit (PDRUNCFG0.PDEN_RNG) and
        // setting AHB RNG clock bit in AHBCLKCTRL.RNG register (AHBCLKCTRLSET2 =
        // 0x00002000).
        self.pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredon());
        self.syscon.enable_clock(Peripheral::Rng);

        // Assert TRNG RESET by setting PRESETCTRL2.RNG_RST bit.
        // Release TRNG Reset by clearing PRESETCTRL2.RNG_RST bit. Set other TRNG
        // registers to the default value.
        // Note: When the device wakes up from Power Down mode, the TRNG module
        // reset must be asserted before its use.
        // reset RNG
        self.syscon.enter_reset(Peripheral::Rng);
        self.syscon.leave_reset(Peripheral::Rng);

        let mut retry = 0;
        loop {
            // For revision 1B, the recommendation is to perform CHI computing only
            // on one specific unprecise clock by selecting COUNTER_CFG.CLOCK_SEL = 4.
            // This setting is needed to accumulating linear entropy.
            // Set COUNTER_CFG.CLOCK_SEL = 4 to perform CHI SQUARED Test and
            // activate CHI computing with ONLINE_TEST_CFG.ACTIVATE = 1.
            self.rng
                .counter_cfg
                .modify(|_, w| unsafe { w.clock_sel().bits(4) });
            self.rng
                .online_test_cfg
                .modify(|_, w| w.activate().set_bit());

            // At power on ONLINE_TEST_VAL.MIN_CHI_SQUARED value is higher than
            // ONLINE_TEST_VAL.MAX_CHI_SQUARED. Wait until
            // ONLINE_TEST_VAL.MIN_CHI_SQUARED decreases and becomes smaller than
            // ONLINE_TEST_VAL.MAX_CHI_SQUARED value.
            let mut retry_chi_min = 0;
            while self.rng.online_test_val.read().min_chi_squared().bits()
                >= self.rng.online_test_val.read().max_chi_squared().bits()
            {
                if retry_chi_min < RETRY_MAX {
                    retry_chi_min += 1;
                    hl::sleep_for(1);
                } else {
                    return Err(RngError::TimeoutChi2Min);
                }
            }

            // If ONLINE_TEST_VAL.MAX_CHI_SQUARED > 4, program
            // ONLINE_TEST_CFG.ACTIVATE = 0 (to reset), if COUNTER_CFG.SHIFT4X < 7,
            // increment COUNTER_CFG.SHIFT4X then go back to step 2. This will start
            // accumulating entropy.
            // When ONLINE_TEST_VAL.MAX_CHI_SQUARED < 4, initialization is now
            // complete.
            if self.rng.online_test_val.read().max_chi_squared().bits() > 4 {
                self.rng
                    .online_test_cfg
                    .modify(|_, w| w.activate().clear_bit());
                if self.rng.counter_cfg.read().shift4x().bits() < 7 {
                    self.rng.counter_cfg.modify(|r, w| unsafe {
                        w.shift4x().bits(r.shift4x().bits() + 1)
                    });
                }
                if retry < RETRY_MAX {
                    hl::sleep_for(1);
                    retry += 1;
                } else {
                    return Err(RngError::TimeoutChi2Gt4);
                }
            } else {
                break;
            }
        }
        Ok(())
    }
    // Read RNG register per user manual v2.4, section 48.15.6, 2021-10-08
    fn read(&self) -> Result<u32, RngError> {
        // if the oscilator is powered off, we won't get good RNG.
        if self.pmc.pdruncfg0.read().pden_rng().is_poweredoff() {
            return Err(RngError::PoweredOff);
        }

        // 1. Keep Clocks CHI computing active.
        // 2. Wait for COUNTER_VAL.REFRESH_CNT to become 31 to refill fresh entropy
        //    since last reading of a random number.
        let mut retry = 0;
        while self.rng.counter_val.read().refresh_cnt().bits() != 31 {
            if retry < RETRY_MAX {
                hl::sleep_for(1);
                retry += 1;
            } else {
                return Err(RngError::TimeoutRefreshCnt);
            }
        }
        // 3. Read new Random number by reading RANDOM_NUMBER register. This will
        //    reset COUNTER_VAL.REFRESH_CNT to zero.
        let number = self.rng.random_number.read().bits();
        // 4. Perform online CHI computing check by checking
        //    ONLINE_TEST_VAL.MAX_CHI_SQUARED value. Wait till
        //    ONLINE_TEST_VAL.MAX_CHI_SQUARED becomes smaller or equal than 4.
        retry = 0;
        while self.rng.online_test_val.read().max_chi_squared().bits() > 4 {
            if retry < RETRY_MAX {
                hl::sleep_for(1);
                retry += 1;
            } else {
                return Err(RngError::TimeoutChi2Gt4);
            }
        }
        // 5. Go to step 2 and read new random number.
        // NOTE: calling this function again is equivalent to 'go to step 2'
        Ok(number)
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
            let ent = self.read()?;
            dest[cnt..cnt + STEP].clone_from_slice(&ent.to_ne_bytes());
            cnt += STEP;
        }
        // fill in remaining
        let remain = len - cnt;
        if remain > STEP {
            panic!("RNG state machine bork");
        }
        if remain > 0 {
            let ent = self.read()?;
            dest[len - remain..].clone_from_slice(&ent.to_ne_bytes());
        }
        Ok(())
    }
}

// low-budget rand::rngs::adapter::ReseedingRng w/o fork stuff
struct ReseedingRng<T: SeedableRng> {
    inner: T,
    reseeder: Lpc55Rng,
    threshold: usize,
    bytes_until_reseed: usize,
}

impl<T> ReseedingRng<T>
where
    T: SeedableRng,
{
    fn new(mut reseeder: Lpc55Rng, threshold: usize) -> Result<Self, Error> {
        use ::core::usize::MAX;

        let threshold = if threshold == 0 { MAX } else { threshold };

        // try_trait_v2 is still experimental
        let inner = match T::from_rng(&mut reseeder) {
            Ok(rng) => rng,
            Err(err) => return Err(err),
        };
        Ok(ReseedingRng {
            inner,
            reseeder,
            threshold,
            bytes_until_reseed: threshold,
        })
    }
}

impl<T> RngCore for ReseedingRng<T>
where
    T: SeedableRng + RngCore,
{
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
        let num_bytes = dest.len();
        if num_bytes >= self.bytes_until_reseed || num_bytes >= self.threshold {
            // try_trait_v2 is still experimental
            self.inner = match T::from_rng(&mut self.reseeder) {
                Ok(rng) => rng,
                Err(e) => return Err(e),
            };
            self.bytes_until_reseed = self.threshold;
        } else {
            self.bytes_until_reseed -= num_bytes;
        }
        self.inner.try_fill_bytes(dest)
    }
}

struct Lpc55RngServer(ReseedingRng<ChaCha20Rng>);

impl Lpc55RngServer {
    fn new(reseeder: Lpc55Rng, threshold: usize) -> Result<Self, Error> {
        Ok(Lpc55RngServer {
            0: ReseedingRng::new(reseeder, threshold)?,
        })
    }
}

impl idl::InOrderRngImpl for Lpc55RngServer {
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
            self.0
                .try_fill_bytes(&mut buf)
                .map_err(|e| RequestError::Runtime(RngError::from(e)))?;
            dest.write_range(cnt..cnt + STEP, &buf)
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += STEP;
        }
        // fill in remaining
        let remain = dest.len() - cnt;
        if remain > STEP {
            panic!("RNG state machine bork");
        }
        if remain > 0 {
            self.0
                .try_fill_bytes(&mut buf)
                .map_err(|e| RequestError::Runtime(RngError::from(e)))?;
            dest.write_range(dest.len() - remain..dest.len(), &buf)
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += remain;
        }
        Ok(cnt)
    }
}

#[export_name = "main"]
fn main() -> ! {
    let rng = Lpc55Rng::new();
    rng.init().expect("Rng failed init");
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
