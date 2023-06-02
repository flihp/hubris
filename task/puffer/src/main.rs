// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Puffer is a task that reads various state information out of the PUF
//! and reports it through the ringbuf.

#![no_std]
#![no_main]

use lpc55_puf::Puf;
use ringbuf::{ringbuf, ringbuf_entry};
use userlib::{hl, TaskId, UnwrapLite};

#[derive(Copy, Clone, PartialEq)]
enum Permission {
    Allowed,
    Denied,
}

#[derive(Copy, Clone, PartialEq)]
enum Status {
    Disabled,
    Enabled,
}

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Enroll(Permission),
    GenerateKey(Permission),
    GetKey(Permission),
    IdxblkH(u32),
    IdxblkHighLocked(bool),
    IdxblkL(u32),
    IdxblkLowLocked(bool),
    PwrSram(Status),
    PwrSramReady(bool),
    SramPwrToggle,
    SramPwrRetryEnable,
    SramPwrTransTo(Status),
    Start(Permission),
    None,
}

ringbuf!(Trace, 32, Trace::None);

struct Puffer<'a> {
    puf: Puf<'a>,
}

impl<'a> Puffer<'a> {
    fn new(puf: Puf<'a>) -> Self {
        Self { puf }
    }

    fn enroll_check(&self) {
        if self.puf.is_enroll_allowed() {
            ringbuf_entry!(Trace::Enroll(Permission::Allowed));
        } else {
            ringbuf_entry!(Trace::Enroll(Permission::Denied));
        }
    }

    fn start_check(&self) {
        if self.puf.is_start_allowed() {
            ringbuf_entry!(Trace::Start(Permission::Allowed));
        } else {
            ringbuf_entry!(Trace::Start(Permission::Denied));
        }
    }

    fn generate_key_check(&self) {
        if self.puf.is_generatekey_allowed() {
            ringbuf_entry!(Trace::GenerateKey(Permission::Allowed));
        } else {
            ringbuf_entry!(Trace::GenerateKey(Permission::Denied));
        }
    }

    fn get_key_check(&self) {
        if self.puf.is_getkey_allowed() {
            ringbuf_entry!(Trace::GetKey(Permission::Allowed));
        } else {
            ringbuf_entry!(Trace::GetKey(Permission::Denied));
        }
    }

    fn dump_idxblk_h(&self) {
        ringbuf_entry!(Trace::IdxblkH(self.puf.get_idxblk_h()));
    }

    fn dump_idxblk_l(&self) {
        ringbuf_entry!(Trace::IdxblkL(self.puf.get_idxblk_l()));
    }

    fn idxblk_l_lock_check(&self) {
        ringbuf_entry!(Trace::IdxblkLowLocked(self.puf.is_idxblk_l_locked()));
    }

    fn idxblk_h_lock_check(&self) {
        ringbuf_entry!(Trace::IdxblkHighLocked(self.puf.is_idxblk_h_locked()));
    }

    fn dump_pwr_ctrl(&self) {
        if self.puf.is_sram_on() {
            ringbuf_entry!(Trace::PwrSram(Status::Enabled));
        } else {
            ringbuf_entry!(Trace::PwrSram(Status::Disabled));
        }
        ringbuf_entry!(Trace::PwrSramReady(self.puf.is_sram_ready()))
    }

    fn turn_sram_on(&self) {
        self.puf.enable_sram();
        if !self.puf.is_sram_ready() {
            hl::sleep_for(40);
            self.puf.enable_sram();
        }
        if !self.puf.is_sram_ready() {
            panic!("PUF SRAM enable failed.");
        }
    }

    fn sram_off_and_on_again(&self) {
        ringbuf_entry!(Trace::SramPwrToggle);
        if !self.puf.is_sram_on() {
            ringbuf_entry!(Trace::SramPwrTransTo(Status::Enabled));
            self.turn_sram_on();
        }

        ringbuf_entry!(Trace::SramPwrTransTo(Status::Disabled));
        self.puf.disable_sram();

        ringbuf_entry!(Trace::SramPwrTransTo(Status::Enabled));
        self.puf.enable_sram();

        if !self.puf.is_sram_ready() {
            ringbuf_entry!(Trace::SramPwrRetryEnable);
            hl::sleep_for(40);
            self.puf.enable_sram();
        }

        if !self.puf.is_sram_ready() {
            panic!("PUF SRAM enable failed.");
        }
    }
}

#[export_name = "main"]
fn main() -> () {
    let peripherals = lpc55_pac::Peripherals::take().unwrap_lite();
    let puf = Puf::new(&peripherals.PUF);
    let puffer = Puffer::new(puf);

    // The state of the lock registers will depend on the code executed before
    // hubris:
    // - a board booted w/o configuring DICE in the CMPA will have all keys
    // unblocked and unlocked
    // - with DICE enabled, but no dice feature enabled in the hubris kernel /
    // pre-main index 15 will be blocked and idxblk_h locked
    // - with DICE enabled in both the CMPA & hubris pre-main index 1 & 15 will
    // be blocked and both idxblk_l & h locked
    puffer.dump_idxblk_l();
    puffer.idxblk_l_lock_check();
    puffer.dump_idxblk_h();
    puffer.idxblk_h_lock_check();

    // If the PUF had been enrolled and started previously (DICE enabled via
    // the CMPA)
    // - enroll will be denied (already enrolled)
    // - generate & get key will be allowed
    // - start will be denied
    // If the PUF has not been enrolled & started
    // - enroll will be allowed
    // - all else will be denied
    puffer.enroll_check();
    puffer.generate_key_check();
    puffer.get_key_check();
    puffer.start_check();

    // toggle PUF SRAM power state
    puffer.dump_pwr_ctrl();
    puffer.sram_off_and_on_again();
    puffer.dump_pwr_ctrl();

    // Toggling the PUF SRAM resets some of the PUF state. If the PUF had been
    // enrolled and started previously (DICE enabled via the CMPA), after
    // reset
    // - enroll will remain disabled (already enrolled)
    // - generate & get key will be disabled
    // - start will be enabled
    puffer.enroll_check();
    puffer.generate_key_check();
    puffer.get_key_check();
    puffer.start_check();

    // Wait for a notification that will never come
    if userlib::sys_recv_closed(&mut [], 1, TaskId::KERNEL).is_err() {
        panic!();
    }
}
