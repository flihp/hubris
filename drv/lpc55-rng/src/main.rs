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
use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::{impls, Error, RngCore, SeedableRng};
use ringbuf::*;
use userlib::*;

use lpc55_pac as device;

task_slot!(SYSCON, syscon_driver);

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Fill(usize),
    Init,
    InitDone,
    RefreshCnt,
    Read,
    ReadDone,
    None,
}

ringbuf!(Trace, 64, Trace::None);

struct Lpc55Core {
    pmc: &'static lpc55_pac::pmc::RegisterBlock,
    rng: &'static lpc55_pac::rng::RegisterBlock,
    syscon: Syscon,
}

const RETRY_MAX: u8 = 5;
impl Lpc55Core {
    fn new() -> Self {
        let syscon = SYSCON.get_task_id();
        Lpc55Core {
            pmc: unsafe { &*device::PMC::ptr() },
            rng: unsafe { &*device::RNG::ptr() },
            syscon: Syscon::from(syscon),
        }
    }

    // Initialization per user manual v2.4, section 48.15.5, 2021-10-08
    fn init(&self) -> Result<(), RngError> {
        ringbuf_entry!(Trace::Init);
        // Enable RNG input clock by clearing power down bit (PDRUNCFG0.PDEN_RNG) and
        // setting AHB RNG clock bit in AHBCLKCTRL.RNG register (AHBCLKCTRLSET2 =
        // 0x00002000).
        self.pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredon());
        self.syscon
            .enable_clock(Peripheral::Rng)
            .expect("enable_clock");

        // Assert TRNG RESET by setting PRESETCTRL2.RNG_RST bit.
        // Release TRNG Reset by clearing PRESETCTRL2.RNG_RST bit. Set other TRNG
        // registers to the default value.
        // Note: When the device wakes up from Power Down mode, the TRNG module
        // reset must be asserted before its use.
        // reset RNG
        self.syscon
            .enter_reset(Peripheral::Rng)
            .expect("enter_reset");
        self.syscon
            .leave_reset(Peripheral::Rng)
            .expect("leave_reset");

        ringbuf_entry!(Trace::InitDone);
        Ok(())
    }
    // Read RNG register per user manual v2.4, section 48.15.6, 2021-10-08
    fn read(&self) -> Result<u32, RngError> {
        ringbuf_entry!(Trace::Read);
        // if the oscilator is powered off, we won't get good RNG.
        if self.pmc.pdruncfg0.read().pden_rng().is_poweredoff() {
            return Err(RngError::PoweredOff);
        }

        // 1. Keep Clocks CHI computing active.
        // 2. Wait for COUNTER_VAL.REFRESH_CNT to become 31 to refill fresh entropy
        //    since last reading of a random number.
        let mut retry = 0;
        while self.rng.counter_val.read().refresh_cnt().bits() != 31 {
            ringbuf_entry!(Trace::RefreshCnt);
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
        // 5. Go to step 2 and read new random number.
        // NOTE: calling this function again is equivalent to 'go to step 2'
        ringbuf_entry!(Trace::ReadDone);
        Ok(number)
    }
}

impl BlockRngCore for Lpc55Core {
    type Item = u32;
    type Results = [u32; 1];

    fn generate(&mut self, results: &mut Self::Results) {
        results[0] = self.read().expect("Lpc55Core read()");
    }
}

struct Lpc55Rng(BlockRng<Lpc55Core>);

impl Lpc55Rng {
    fn new() -> Self {
        Lpc55Rng(BlockRng::new(Lpc55Core::new()))
    }

    fn init(&self) -> Result<(), RngError> {
        self.0.core.init()
    }
}

impl RngCore for Lpc55Rng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes)
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        if self.0.core.pmc.pdruncfg0.read().pden_rng().bits() {
            return Err(RngError::PoweredOff.into());
        }

        self.0.try_fill_bytes(bytes)
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

struct Lpc55RngServer(Lpc55Rng);

impl Lpc55RngServer {
    fn new(rng: Lpc55Rng) -> Self {
        Lpc55RngServer(rng)
    }
}

impl idl::InOrderRngImpl for Lpc55RngServer {
    fn fill(
        &mut self,
        _: &userlib::RecvMessage,
        dest: idol_runtime::Leased<idol_runtime::W, [u8]>,
    ) -> Result<usize, RequestError<RngError>> {
        ringbuf_entry!(Trace::Fill(dest.len()));
        let mut cnt = 0;
        const STEP: usize = size_of::<u32>();
        let mut buf = [0u8; STEP];
        // fill in multiples of STEP / RNG register size
        for _ in 0..(dest.len() / STEP) {
            self.0.try_fill_bytes(&mut buf).map_err(RngError::from)?;
            dest.write_range(cnt..cnt + STEP, &buf)
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;
            cnt += STEP;
        }
        // fill in remaining
        let remain = dest.len() - cnt;
        assert!(remain < STEP);
        if remain > 0 {
            self.0.try_fill_bytes(&mut buf).map_err(RngError::from)?;
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

    let mut rng = Lpc55RngServer::new(rng);

    let mut buffer = [0u8; idl::INCOMING_SIZE];

    loop {
        idol_runtime::dispatch(&mut buffer, &mut rng);
    }
}

mod idl {
    use drv_rng_api::RngError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
