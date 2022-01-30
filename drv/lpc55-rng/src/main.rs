// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Random Number Generation
//!
//! This task will produce random u32 values for you, if you ask nicely.
//!
//! An example:
//!
//! ```ignore
//! #[derive(AsBytes)]
//! #[repr(C)]
//! struct FetchRandomNumber;
//!
//! impl hl::Call for FetchRandomNumber {
//!     const OP: u16 = 0;
//!     type Response = u32;
//!     type Err = u32;
//! }
//!
//! let num = hl::send(rng, &FetchRandomNumber).expect("could not ask the rng for a number");
//!
//! hprintln!("got {} from the rng", num).ok();
//! ```

#![no_std]
#![no_main]

use drv_lpc55_syscon_api::{Peripheral, Syscon};
use userlib::*;
use zerocopy::AsBytes;
use drv_rng_api::RngError;

use ringbuf::*;

use lpc55_pac as device;

task_slot!(SYSCON, syscon_driver);

struct Rng {
    rng: &'static lpc55_pac::rng::RegisterBlock
}

impl From<&'static lpc55_pac::rng::RegisterBlock> for Rng {
    fn from(rng: &'static lpc55_pac::rng::RegisterBlock) -> Self {
        Rng { rng }
    }
}

impl Rng {
    // Initialization per user manual v2.4, section 48.15.5, 2021-10-08
    fn init(
        &self,
        pmc: &lpc55_pac::pmc::RegisterBlock,
        syscon: Syscon,
    ){
        // Enable RNG input clock by clearing power down bit (PDRUNCFG0.PDEN_RNG) and
        // setting AHB RNG clock bit in AHBCLKCTRL.RNG register (AHBCLKCTRLSET2 =
        // 0x00002000).
        ringbuf_entry!(Trace::RngPoweredOn);
        pmc.pdruncfg0.modify(|_, w| w.pden_rng().poweredon());
        ringbuf_entry!(Trace::RngClockOn);
        syscon.enable_clock(Peripheral::Rng);

        // Assert TRNG RESET by setting PRESETCTRL2.RNG_RST bit.
        // Release TRNG Reset by clearing PRESETCTRL2.RNG_RST bit. Set other TRNG
        // registers to the default value.
        // Note: When the device wakes up from Power Down mode, the TRNG module
        // reset must be asserted before its use.
        // reset RNG
        ringbuf_entry!(Trace::ResetEnter);
        syscon.enter_reset(Peripheral::Rng);
        ringbuf_entry!(Trace::ResetLeave);
        syscon.leave_reset(Peripheral::Rng);

        loop {
            // For revision 1B, the recommendation is to perform CHI computing only
            // on one specific unprecise clock by selecting COUNTER_CFG.CLOCK_SEL = 4.
            // This setting is needed to accumulating linear entropy.
            // Set COUNTER_CFG.CLOCK_SEL = 4 to perform CHI SQUARED Test and
            // activate CHI computing with ONLINE_TEST_CFG.ACTIVATE = 1.
            ringbuf_entry!(Trace::ClockSel);
            self.rng.counter_cfg.modify(|_, w| unsafe {
                w.clock_sel().bits(4)
            });
            ringbuf_entry!(Trace::ChiActivate);
            self.rng.online_test_cfg.modify(|_, w| w.activate().set_bit());

            // At power on ONLINE_TEST_VAL.MIN_CHI_SQUARED value is higher than
            // ONLINE_TEST_VAL.MAX_CHI_SQUARED. Wait until
            // ONLINE_TEST_VAL.MIN_CHI_SQUARED decreases and becomes smaller than
            // ONLINE_TEST_VAL.MAX_CHI_SQUARED value.
            ringbuf_entry!(Trace::ChiWaitBegin);
            while
                self.rng.online_test_val.read().min_chi_squared().bits() >=
                self.rng.online_test_val.read().max_chi_squared().bits()
            {
                let min = rng.online_test_val.read().min_chi_squared().bits();
                ringbuf_entry!(Trace::ChiMin(min));
                let max = rng.online_test_val.read().max_chi_squared().bits();
                ringbuf_entry!(Trace::ChiMax(max));
            }
            ringbuf_entry!(Trace::ChiWaitEnd);

            // If ONLINE_TEST_VAL.MAX_CHI_SQUARED > 4, program
            // ONLINE_TEST_CFG.ACTIVATE = 0 (to reset), if COUNTER_CFG.SHIFT4X < 7,
            // increment COUNTER_CFG.SHIFT4X then go back to step 2. This will start
            // accumulating entropy.
            // When ONLINE_TEST_VAL.MAX_CHI_SQUARED < 4, initialization is now
            // complete.
            let max_chi2 = self
                .rng.online_test_val
                .read()
                .max_chi_squared()
                .bits();
            ringbuf_entry!(Trace::MaxChi2(max_chi2));
            if max_chi2 > 4 {
                ringbuf_entry!(Trace::ChiDeactivate);
                self.rng.online_test_cfg.modify(|_, w| {
                    w.activate().clear_bit()
                });
                if self.rng.counter_cfg.read().shift4x().bits() < 7 {
                    ringbuf_entry!(Trace::Shift4xInc);
                    self.rng.counter_cfg.modify(|r, w| {
                        unsafe { w.shift4x().bits(r.shift4x().bits() + 1) }
                    });
                }
            } else {
                ringbuf_entry!(Trace::InitEnd);
                break;
            }
        }
    }

    // Read RNG register per user manual v2.4, section 48.15.6, 2021-10-08
    fn read(&self) -> u32 {
        // 1. Keep Clocks CHI computing active.
        // 2. Wait for COUNTER_VAL.REFRESH_CNT to become 31 to refill fresh entropy
        //    since last reading of a random number.
        while self.rng.counter_val.read().refresh_cnt().bits() != 31 {
            ringbuf_entry!(Trace::RefreshCnt);
        }
        // 3. Read new Random number by reading RANDOM_NUMBER register. This will
        //    reset COUNTER_VAL.REFRESH_CNT to zero.
        let number = self.rng.random_number.read().bits();
        // 4. Perform online CHI computing check by checking
        //    ONLINE_TEST_VAL.MAX_CHI_SQUARED value. Wait till
        //    ONLINE_TEST_VAL.MAX_CHI_SQUARED becomes smaller or equal than 4.
        while self.rng.online_test_val.read().max_chi_squared().bits() > 4 {
            ringbuf_entry!(Trace::MaxChi4);
        }
        // 5. Go to step 2 and read new random number.
        // NOTE: calling this function again is equivalent to 'go to step 2'
        number
    }
}

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    InitBegin,
    InitEnd,
    LoopBegin,
    MsgBegin,
    RngClockOn,
    RngClockOff,
    RngPoweredOn,
    RngPoweredOff,
    ResetEnter,
    ResetLeave,
    ClockSel,
    ChiActivate,
    ChiDeactivate,
    ChiWaitBegin,
    ChiWaitEnd,
    ChiMin(u8),
    ChiMax(u8),
    MaxChi2(u8),
    Shift4xInc,
    RefreshCnt,
    MaxChi4,
    Read(usize),
    MsgEnd,
    None,
}

ringbuf!(Trace, 64, Trace::None);

#[export_name = "main"]
fn main() -> ! {
    let syscon = SYSCON.get_task_id();
    let syscon = Syscon::from(syscon);
    let pmc = unsafe { &*device::PMC::ptr() };
    let rng = unsafe { &*device::RNG::ptr() };

    rand_init(rng, pmc, syscon);

    let rng = Rng::from(unsafe { &*device::RNG::ptr() });
    rng.init(pmc, syscon);

    let mut buffer = [0u32; 1];

    loop {
        ringbuf_entry!(Trace::LoopBegin);
        hl::recv_without_notification(
            buffer.as_bytes_mut(),
            |_op: u16, msg| -> Result<(), RngError> {
                let (_msg, caller) =
                    msg.fixed_with_leases::<(), usize>(1).ok_or(RngError::BadArg)?;
                ringbuf_entry!(Trace::MsgBegin);

                // if the oscilator is powered off, we won't get good RNG.
                if pmc.pdruncfg0.read().pden_rng().is_poweredoff() {
                    return Err(RngError::PoweredOff);
                }

                let borrow = caller.borrow(0);
                let borrow_info =
                    borrow.info().ok_or(RngError::BadArg)?;

                if !borrow_info.attributes.contains(LeaseAttributes::WRITE) {
                    return Err(RngError::BadArg);
                }

                let mut cnt = 0;
                ringbuf_entry!(Trace::Read(cnt));
                const STEP: usize = 4; // sizeof(u32)
                for i in 0..(borrow_info.len / STEP) {
                    let number = rng.read();
                    borrow.write_at(i * STEP, number);
                    cnt += STEP;
                    ringbuf_entry!(Trace::Read(cnt));
                }

                let remain = borrow_info.len % STEP;
                if remain > 0 {
                    let ent = rng.read().to_ne_bytes();
                    borrow.write_fully_at(borrow_info.len - remain, &ent[0..remain]);
                    cnt += remain;
                    ringbuf_entry!(Trace::Read(cnt));
                }

                ringbuf_entry!(Trace::MsgEnd);
                caller.reply(cnt);

                Ok(())
            },
        );
    }
}
