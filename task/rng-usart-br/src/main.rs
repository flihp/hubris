// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use drv_rng_api::{Rng, RngCore};
use ringbuf::{ringbuf, ringbuf_entry};
use userlib::{sys_send, task_slot, Lease};

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Code(u32),
    Init,
    InitDone,
    Loop,
    None,
}

ringbuf!(Trace, 64, Trace::None);
task_slot!(RNG, rng_driver);
task_slot!(UART, usart_driver);


#[export_name = "main"]
fn main() -> ! {
    ringbuf_entry!(Trace::Init);

    let mut buf: [u8; 128] = [0; 128];
    let mut rng = Rng::from(RNG.get_task_id());

    let usart = UART.get_task_id();

    ringbuf_entry!(Trace::InitDone);

    const OP_WRITE: u16 = 1;
    loop {
        rng.try_fill_bytes(&mut buf)
            .expect("Failed to get entropy from RNG.");
        let (code, _) =
            sys_send(usart, OP_WRITE, &[], &mut [], &[Lease::from(&buf[..])]);
        if code != 0 {
            ringbuf_entry!(Trace::Code(code));
        }
        ringbuf_entry!(Trace::Loop);
    }
}
