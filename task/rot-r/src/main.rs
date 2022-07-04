// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use dice::{
    serial_certs::{CertType, Msg},
    AliasHandoff, SeedBuf,
};
use lib_lpc55_usart as usart;
use lpc55_pac as device;
use ringbuf::{ringbuf, ringbuf_entry};
use salty::signature::Keypair;
use userlib::{hl, task_slot, TaskId, UnwrapLite};

task_slot!(GPIO, gpio_driver);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Trace {
    AliasCertSize(usize),
    DeviceIdCertSize(usize),
    PollForCertReq,
    UsartError(usart::Error),
    GotMsg(usize),
    GotCertPlz(CertType),
    BadState,
    MaxEncodedBufSize(usize),
    Sending(usize),
    None,
}

ringbuf!(Trace, 64, Trace::None);

#[export_name = "main"]
fn main() -> ! {
    let gpio_driver = GPIO.get_task_id();
    setup_pins(gpio_driver).unwrap_lite();

    let peripherals = device::Peripherals::take().unwrap_lite();

    let usart = peripherals.USART0;
    let flexcomm0 = peripherals.FLEXCOMM0;

    let mut usart = usart::Usart::turn_on(&flexcomm0, &usart);

    ringbuf_entry!(Trace::MaxEncodedBufSize(Msg::MAX_ENCODED_SIZE));
    let mut data = [0u8; Msg::MAX_ENCODED_SIZE];

    // get dice artifacts from memory
    let alias_handoff = AliasHandoff::from_mem();
    ringbuf_entry!(Trace::DeviceIdCertSize(alias_handoff.deviceid_cert.len()));
    ringbuf_entry!(Trace::AliasCertSize(alias_handoff.alias_cert.len()));

    let _alias_keypair = Keypair::from(alias_handoff.seed.as_bytes());

    loop {
        ringbuf_entry!(Trace::PollForCertReq);
        let msg = match usart.read_until(&mut data, &[0]) {
            Ok(size) => {
                ringbuf_entry!(Trace::GotMsg(size));
                Msg::from(&data[..size])
            }
            Err(e) => {
                ringbuf_entry!(Trace::UsartError(e));
                continue;
            }
        };

        let size = match msg {
            Msg::CertPlz(CertType::DeviceId) => {
                ringbuf_entry!(Trace::GotCertPlz(CertType::DeviceId));
                let msg = Msg::DeviceIdCert(alias_handoff.deviceid_cert);
                msg.encode(&mut data)
            }
            Msg::CertPlz(CertType::Alias) => {
                ringbuf_entry!(Trace::GotCertPlz(CertType::Alias));
                let msg = Msg::Alias(alias_handoff.alias_cert);
                msg.encode(&mut data)
            }
            _ => {
                ringbuf_entry!(Trace::BadState);
                continue;
            }
        };
        ringbuf_entry!(Trace::Sending(size));
        hl::sleep_for(5000);
        usart.write_all(&data).expect("write_all");
        usart.flush_all();
    }
}

include!(concat!(env!("OUT_DIR"), "/pin_config.rs"));
