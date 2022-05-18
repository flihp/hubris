// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use lib_lpc55_usart::Usart;
use lpc55_pac as device;
use ringbuf::{ringbuf, ringbuf_entry};
use unwrap_lite::UnwrapLite;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Reading,
    Read(usize),
    Writing,
    Write,
    InitDone,
    None,
}

ringbuf!(Trace, 64, Trace::None);

#[export_name = "main"]
fn main() -> ! {
    let peripherals = device::Peripherals::take().unwrap_lite();

    let usart = peripherals.USART0;
    let flexcomm0 = peripherals.FLEXCOMM0;

    cfg_if::cfg_if! {
        if #[cfg(feature = "tasks")] {
            userlib::task_slot!(GPIO, gpio_driver);

            let gpio_driver = GPIO.get_task_id();
            setup_pins(gpio_driver).unwrap_lite();

            let mut usart = Usart::turn_on(&flexcomm0, &usart);
        } else {
            let iocon = peripherals.IOCON;
            let syscon = peripherals.SYSCON;

            let mut usart = Usart::turn_on(&syscon, &iocon, &flexcomm0, &usart);
        }
    }

    ringbuf_entry!(Trace::InitDone);
    let mut buf = [0u8; 1024];
    loop {
        ringbuf_entry!(Trace::Reading);
        // TODO: this function polls the usart, use interrupts
        match usart.read_until(&mut buf, &[b'\r']) {
            Ok(size) => {
                ringbuf_entry!(Trace::Read(size));
                ringbuf_entry!(Trace::Writing);
                match usart.write_all(&buf[..size]) {
                    Ok(_) => {
                        ringbuf_entry!(Trace::Write);
                        buf.fill(0);
                    }
                    Err(_) => panic!("fml write"),
                }
            }
            Err(_) => panic!("fml read"),
        }
    }
}

#[cfg(feature = "tasks")]
use userlib::TaskId;
#[cfg(feature = "tasks")]
include!(concat!(env!("OUT_DIR"), "/pin_config.rs"));
