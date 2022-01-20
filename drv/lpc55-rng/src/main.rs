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

use lpc55_pac as device;

task_slot!(SYSCON, syscon_driver);

#[export_name = "main"]
fn main() -> ! {
    let syscon = SYSCON.get_task_id();
    let syscon = Syscon::from(syscon);

    syscon.enable_clock(Peripheral::Rng);

    let rng = unsafe { &*device::RNG::ptr() };
    let pmc = unsafe { &*device::PMC::ptr() };

    let mut buffer = [0u32; 1];

    loop {
        hl::recv_without_notification(
            buffer.as_bytes_mut(),
            |_op: u16, msg| -> Result<(), RngError> {
                let (_msg, caller) =
                    msg.fixed_with_leases::<(), usize>(1).ok_or(RngError::BadArg)?;

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
                const STEP: usize = 4; // sizeof(u32)
                for i in 0..(borrow_info.len / STEP) {
                    let number = rng.random_number.read().bits();
                    borrow.write_at(i * STEP, number);
                    cnt += STEP;
                }

                let remain = borrow_info.len % STEP;
                if remain > 0 {
                    let ent = rng.random_number.read().bits().to_ne_bytes();
                    borrow.write_fully_at(borrow_info.len - remain, &ent[0..remain]);
                    cnt += remain;
                }

                caller.reply(cnt);

                Ok(())
            },
        );
    }
}
