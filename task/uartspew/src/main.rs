// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use userlib::{task_slot, sys_send, Lease};
use ringbuf::{ringbuf, ringbuf_entry};

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Sent,
    None,
}

ringbuf!(Trace, 32, Trace::None);

task_slot!(UART, usart_driver);

#[export_name = "main"]
fn main() -> ! {
    let peer = UART.get_task_id();
    let msg: &[u8] = b"please work!\r\n";
    const OP_WRITE: u16 = 1;

    loop {
        let (code, _) =
            sys_send(peer, OP_WRITE, &[], &mut [], &[Lease::from(msg)]);
        ringbuf_entry!(Trace::Sent);
        assert_eq!(0, code);
    }
}
