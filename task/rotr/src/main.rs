// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Root of trust for reporting task.
//!
//! Use the rotr-api crate to interact with this task.

#![no_std]
#![no_main]

use dice::{AliasData, CertData};
use idol_runtime::RequestError;
use lpc55_pac as device;
use lpc55_puf::Puf;
use ringbuf::{ringbuf, ringbuf_entry};
use stage0_handoff::HandoffData;
use task_rotr_api::RotrError;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Fwid([u8; MEASUREMENT_LEN]),
    Record([u8; MEASUREMENT_LEN]),
    Startup,
    StatBusy,
    StatSuccess,
    StatError,
    IfStatError,
    AllowEnroll,
    AllowStart,
    AllowSetKey,
    AllowGetKey,
    IdxKeyCode,
    GetKey,
    KeyCode([u32; KEYCODE_LEN]),
    Key([u8; KEY_LEN]),
    KcIdx(usize),
    KeyIdx(usize),
    None,
}

ringbuf!(Trace, 16, Trace::None);

const MAX_MEASUREMENTS: usize = 16;
const MEASUREMENT_LEN: usize = 32;

const KEYCODE_LEN: usize = 13;
const KEY_LEN: usize = 32;
const KEY_INDEX: u32 = 1;

struct RotrServer<'a> {
    _alias: &'a AliasData,
    _certs: &'a CertData,
    offset: usize,
    measurements: [[u8; MEASUREMENT_LEN]; MAX_MEASUREMENTS],
}

impl<'a> RotrServer<'a> {
    fn new(alias: &'a AliasData, certs: &'a CertData) -> Self {
        Self {
            _alias: alias,
            _certs: certs,
            offset: 0,
            measurements: [[0u8; MEASUREMENT_LEN]; MAX_MEASUREMENTS],
        }
    }
}

impl idl::InOrderRotrImpl for RotrServer<'_> {
    fn record(
        &mut self,
        _msg: &userlib::RecvMessage,
        hash: [u8; MEASUREMENT_LEN],
    ) -> Result<(), RequestError<RotrError>> {
        if self.offset < MAX_MEASUREMENTS {
            ringbuf_entry!(Trace::Record(hash));

            self.measurements[self.offset] = hash;
            self.offset += 1;

            Ok(())
        } else {
            Err(RotrError::LogFull.into())
        }
    }
}

fn puf_ringbuf_stat(puf: &Puf) {
    if puf.is_success() {
        ringbuf_entry!(Trace::StatSuccess);
    }
    if puf.is_error() {
        ringbuf_entry!(Trace::StatError);
    }
    if puf.is_busy() {
        ringbuf_entry!(Trace::StatBusy);
    }
}

fn puf_ringbuf_ifstat(puf: &Puf) {
    if puf.is_ifstat_error() {
        ringbuf_entry!(Trace::IfStatError);
    }
}

fn puf_ringbuf_allow(puf: &Puf) {
    if puf.is_enroll_allowed() {
        ringbuf_entry!(Trace::AllowEnroll);
    }
    if puf.is_start_allowed() {
        ringbuf_entry!(Trace::AllowStart);
    }
    if puf.is_generatekey_allowed() {
        ringbuf_entry!(Trace::AllowSetKey);
    }
    if puf.is_getkey_allowed() {
        ringbuf_entry!(Trace::AllowGetKey);
    }
}

#[export_name = "main"]
fn main() -> ! {
    ringbuf_entry!(Trace::Startup);

    let cert_data = match CertData::load() {
        Ok(a) => a,
        Err(_) => panic!("CertData"),
    };

    let alias_data = match AliasData::load() {
        Ok(a) => a,
        Err(_) => panic!("AliasData"),
    };

    let fwid = alias_data.alias_cert.get_fwid();
    ringbuf_entry!(Trace::Fwid(fwid.try_into().unwrap()));

    let peripherals = device::Peripherals::take().unwrap();
    let puf = Puf::new(&peripherals.PUF);

    puf_ringbuf_stat(&puf);
    puf_ringbuf_ifstat(&puf);
    puf_ringbuf_allow(&puf);

    // generate key code
    let mut keycode = [0u32; KEYCODE_LEN];
    if puf.generate_keycode(KEY_INDEX, KEY_LEN, &mut keycode) {
        ringbuf_entry!(Trace::KeyCode(keycode));
    } else {
        panic!("GenerageKeyFailed");
    }

    puf_ringbuf_stat(&puf);
    puf_ringbuf_ifstat(&puf);
    puf_ringbuf_allow(&puf);

    // get key from key code
    let mut key = [0u8; KEY_LEN];
    if puf.get_key(&keycode, &mut key) {
        ringbuf_entry!(Trace::Key(key));
    } else {
        panic!("GetKeyFailed");
    }

    let mut buffer = [0; idl::INCOMING_SIZE];
    let mut rotr = RotrServer::new(&alias_data, &cert_data);
    loop {
        idol_runtime::dispatch(&mut buffer, &mut rotr);
    }
}

mod idl {
    use task_rotr_api::RotrError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
