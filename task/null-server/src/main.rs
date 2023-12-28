// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use null_api::NullError;
use ringbuf::{ringbuf, ringbuf_entry};

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    DstLen(usize),
    None,
    Null,
    SrcLen(usize),
    Start,
    Input,
    InputOutput,
    Output,
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

    fn input(
        &mut self,
        _msg: &userlib::RecvMessage,
        src: idol_runtime::Leased<idol_runtime::R, [u8]>,
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::Input);
        ringbuf_entry!(Trace::SrcLen(src.len()));

        Ok(())
    }

    fn input_output(
        &mut self,
        _msg: &userlib::RecvMessage,
        src: idol_runtime::Leased<idol_runtime::R, [u8]>,
        dst: idol_runtime::Leased<idol_runtime::W, [u8]>,
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::InputOutput);
        ringbuf_entry!(Trace::SrcLen(src.len()));
        ringbuf_entry!(Trace::DstLen(dst.len()));

        if src.len() != dst.len() {
            return Err(NullError::LeasesNotEqual.into());
        }


        // this is an arbitrary upper bound
        let mut buf = [0u8; 1024];
        if src.len() > 1024 {
            return Err(NullError::LeaseTooBig.into());
        }

        src.read_range(0..src.len(), &mut buf)
            .map_err(|_| idol_runtime::RequestError::went_away())?;
        dst.write_range(0..src.len(), &buf[0..src.len()])
            .map_err(|_| idol_runtime::RequestError::went_away())?;

        Ok(())
    }

    fn output(
        &mut self,
        _msg: &userlib::RecvMessage,
        dst: idol_runtime::Leased<idol_runtime::W, [u8]>,
    ) -> Result<(), idol_runtime::RequestError<NullError>> {
        ringbuf_entry!(Trace::Output);
        ringbuf_entry!(Trace::DstLen(dst.len()));

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
    use super::NullError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
