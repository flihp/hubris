// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use null_api::{NullError, NullErrorZ};
use ringbuf::{ringbuf, ringbuf_entry};

const ARRAY_LENGTH: usize = 4;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    ArrayInZerocopy([u8; ARRAY_LENGTH]),
    ArrayInHubpack([u8; ARRAY_LENGTH]),
    ArrayInHubpack16([u8; 16]),
    ArrayInHubpack24([u8; 24]),
    ArrayInHubpack28([u8; 28]),
    ArrayInHubpack30([u8; 30]),
    ArrayInHubpack32([u8; 32]),
    None,
    Null,
    Start,
}

ringbuf!(Trace, 16, Trace::None);

struct NullServer;

impl Default for NullServer {
    fn default() -> Self {
        Self{}
    }
}

impl idl::InOrderNullImpl for NullServer {
    fn null(
        &mut self,
        _msg: &userlib::RecvMessage,
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::Null);

        Ok(())
    }

    fn array_in_zerocopy(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; ARRAY_LENGTH],
    ) -> Result<(), idol_runtime::RequestError<NullErrorZ>> {
        ringbuf_entry!(Trace::ArrayInZerocopy(array));

        Ok(())
    }

    fn array_in_hubpack(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; ARRAY_LENGTH],
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::ArrayInHubpack(array));

        Ok(())
    }

    fn array_in_hubpack_16(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; 16],
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::ArrayInHubpack16(array));

        Ok(())
    }

    fn array_in_hubpack_24(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; 24],
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::ArrayInHubpack24(array));

        Ok(())
    }

    fn array_in_hubpack_28(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; 28],
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::ArrayInHubpack28(array));

        Ok(())
    }

    fn array_in_hubpack_30(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; 30],
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::ArrayInHubpack30(array));

        Ok(())
    }
    fn array_in_hubpack_32(
        &mut self,
        _msg: &userlib::RecvMessage,
        array: [u8; 32],
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::ArrayInHubpack32(array));

        Ok(())
    }
}

#[export_name = "main"]
fn main() {
    ringbuf_entry!(Trace::Start);

    let mut buffer = [0; idl::INCOMING_SIZE];
    let mut null = NullServer::default();

    loop {
        idol_runtime::dispatch(&mut buffer, &mut null);
    }
}

mod idl {
    use super::{NullError, NullErrorZ};

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
