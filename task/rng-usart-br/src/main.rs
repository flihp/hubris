// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use drv_stm32h7_usart as drv_usart;

use drv_usart::Usart;

use drv_rng_api::{Rng, RngCore};
use ringbuf::{ringbuf, ringbuf_entry};
use userlib::task_slot;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Init,
    InitDone,
    Loop,
    RngBufFull,
    TryTxPushDone,
    None,
}

ringbuf!(Trace, 64, Trace::None);
task_slot!(RNG, rng_driver);
task_slot!(SYS, sys);

#[export_name = "main"]
fn main() -> ! {
    ringbuf_entry!(Trace::Init);

    let mut buf: [u8; 128] = [0; 128];
    //let buf: [u8; 6 ] = [ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe ];
    let mut rng = Rng::from(RNG.get_task_id());

    let uart = configure_uart_device();

    ringbuf_entry!(Trace::InitDone);

    loop {
        rng.try_fill_bytes(&mut buf)
            .expect("Failed to get entropy from RNG.");

        write_all(&uart, &buf);

        ringbuf_entry!(Trace::Loop);
    }
}

// write all bytes in buf, block / spin if fifo is full
// NOTE: this does not block till all bytes have been transmitted,
// see flush_all.
pub fn write_all(uart: &Usart, src: &[u8]) {
    for b in src {
        let mut done = false;
        while !done {
            done = uart.try_tx_push(*b);
        }
    }
}

//#[cfg(any(feature = "stm32h743", feature = "stm32h753"))]
fn configure_uart_device() -> Usart {
    use drv_usart::device;
    use drv_usart::drv_stm32xx_sys_api::*;

    // TODO: this module should _not_ know our clock rate. That's a hack.
    const CLOCK_HZ: u32 = 100_000_000;

    const BAUD_RATE: u32 = 1_500_000;

    let usart;
    let peripheral;
    let pins;

    cfg_if::cfg_if! {
        if #[cfg(feature = "usart1")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::B.pin(6).and_pin(7), Alternate::AF7),
            ];

            // From thin air, pluck a pointer to the USART register block.
            //
            // Safety: this is needlessly unsafe in the API. The USART is
            // essentially a static, and we access it through a & reference so
            // aliasing is not a concern. Were it literally a static, we could
            // just reference it.
            usart = unsafe { &*device::USART1::ptr() };
            peripheral = Peripheral::Usart1;
            pins = PINS;
        } else if #[cfg(feature = "usart2")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::D.pin(5).and_pin(6), Alternate::AF7),
            ];
            usart = unsafe { &*device::USART2::ptr() };
            peripheral = Peripheral::Usart2;
            pins = PINS;
        } else if #[cfg(feature = "usart3")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::D.pin(8).and_pin(9), Alternate::AF7),
            ];
            usart = unsafe { &*device::USART3::ptr() };
            peripheral = Peripheral::Usart3;
            pins = PINS;
        } else if #[cfg(feature = "uart4")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::D.pin(0).and_pin(1), Alternate::AF8),
            ];
            usart = unsafe { &*device::UART4::ptr() };
            peripheral = Peripheral::Uart4;
            pins = PINS;
        } else if #[cfg(feature = "uart5")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::C.pin(12), Alternate::AF8),
                (Port::D.pin(2), Alternate::AF8),
            ];
            usart = unsafe { &*device::UART5::ptr() };
            peripheral = Peripheral::Uart5;
            pins = PINS;
        } else if #[cfg(feature = "usart6")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::C.pin(6).and_pin(7), Alternate::AF7),
            ];
            usart = unsafe { &*device::USART6::ptr() };
            peripheral = Peripheral::Usart6;
            pins = PINS;
        } else if #[cfg(feature = "uart7")] {
            const PINS: &[(PinSet, Alternate)] = &[
                (Port::E.pin(7).and_pin(8), Alternate::AF7),
            ];
            usart = unsafe { &*device::UART7::ptr() };
            peripheral = Peripheral::Uart7;
            pins = PINS;
        } else {
            compile_error!("no usartX/uartX feature specified");
        }
    }

    Usart::turn_on(
        &Sys::from(SYS.get_task_id()),
        usart,
        peripheral,
        pins,
        CLOCK_HZ,
        BAUD_RATE,
    )
}
