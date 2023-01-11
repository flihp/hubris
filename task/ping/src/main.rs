// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use core::mem;
use lpc55_pac::Peripherals;
use lpc55_puf::Puf;
use ringbuf::{ringbuf, ringbuf_entry};
use userlib::*;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    KeyCode([u32; KEYCODE_LEN]),
    Seed([u8; SEED_LEN]),
    IdxBlkL(u32),
    IdxBlkH(u32),
    GetKeyFail,
    None,
}
ringbuf!(Trace, 32, Trace::None);

pub const SEED_LEN: usize = 32;
pub const KEYCODE_LEN: usize =
    Puf::key_to_keycode_len(SEED_LEN) / mem::size_of::<u32>();
pub const KEY_INDEX: u32 = 1;

task_slot!(PEER, peer);
#[cfg(feature = "uart")]
task_slot!(UART, usart_driver);

#[inline(never)]
fn nullread() {
    unsafe {
        // This constant is in a region we can't access; memory fault
        (BAD_ADDRESS as *const u8).read_volatile();
    }
}

// Only ARMv7-M and newer have hardware divide instructions
#[cfg(any(armv7m, armv8m))]
#[inline(never)]
fn divzero() {
    unsafe {
        // Divide by 0
        let p: u32 = 123;
        let q: u32 = 0;
        let _res: u32;
        core::arch::asm!("udiv r2, r1, r0", in("r1") p, in("r0") q, out("r2") _res);
    }
}

fn use_index(puf: &Puf, index: u32) -> bool {
    let mut keycode = [0u32; KEYCODE_LEN];
    if !puf.generate_keycode(index, SEED_LEN, &mut keycode) {
        panic!("failed to generate key code");
    }
    ringbuf_entry!(Trace::KeyCode(keycode));

    // get keycode from DICE MFG flash region
    // good opportunity to put a magic value in the DICE MFG flash region
    let mut seed = [0u8; SEED_LEN];
    if puf.get_key(&keycode, &mut seed) {
        let seed = seed;
        ringbuf_entry!(Trace::Seed(seed));
    } else {
        ringbuf_entry!(Trace::GetKeyFail);
    }
    true
}

fn dump_idxblks(puf: &Puf) {
    ringbuf_entry!(Trace::IdxBlkL(puf.get_idxblk_l()));
    ringbuf_entry!(Trace::IdxBlkH(puf.get_idxblk_h()));

    // The IDXBLK_(L|H)_DP registers don't appear to do anything.
    // They're always 0 while the IDXBLK_(L|H) registers work as
    // advertised. If these register sets disagree then the PUF index
    // should be blocked but experimentation shows this isn't the case.
    //
    //ringbuf_entry!(Trace::IdxBlkLDp(puf.get_idxblk_l_dp()));
    //ringbuf_entry!(Trace::IdxBlkHDp(puf.get_idxblk_h_dp()));
}

#[export_name = "main"]
fn main() -> ! {
    let peer = PEER.get_task_id();
    const PING_OP: u16 = 1;
    const FAULT_EVERY: u32 = 100;

    let peripherals = Peripherals::take().unwrap_lite();

    let puf = peripherals.PUF;
    let puf = Puf::new(&puf);
    let key_index = 1;

    dump_idxblks(&puf);
    use_index(&puf, key_index);

    let key_index = 2;

    dump_idxblks(&puf);
    use_index(&puf, key_index);

    //hl::sleep_for(1000);

    //puf.block_index(key_index);
    //puf.lock_indices_low();

    //dump_idxblks(&puf);
    //use_index(&puf, key_index);

    //puf.unblock_index(key_index);
    //dump_idxblks(&puf);
    //use_index(&puf, key_index);

    #[cfg(armv6m)]
    let faultme = [nullread];
    #[cfg(any(armv7m, armv8m))]
    let faultme = [nullread, divzero];

    let mut response = [0; 16];
    loop {
        uart_send(b"Ping!\r\n");

        let (code, _len) =
            sys_send(peer, PING_OP, b"hello", &mut response, &[]);

        if code % FAULT_EVERY != 0 {
            continue;
        }

        let op = (code / FAULT_EVERY) as usize % faultme.len();
        faultme[op]();
        sys_panic(b"unexpected non-fault!");
    }
}

#[cfg(feature = "uart")]
fn uart_send(text: &[u8]) {
    let peer = UART.get_task_id();

    const OP_WRITE: u16 = 1;
    let (code, _) =
        sys_send(peer, OP_WRITE, &[], &mut [], &[Lease::from(text)]);
    assert_eq!(0, code);
}

#[cfg(not(feature = "uart"))]
fn uart_send(_: &[u8]) {}

include!(concat!(env!("OUT_DIR"), "/consts.rs"));
