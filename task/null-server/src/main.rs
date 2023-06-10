// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use null_api::NullError;
use ringbuf::{ringbuf, ringbuf_entry};

#[derive(Copy, Clone, PartialEq)]
enum Trace {
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
