// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Root of trust for reporting task.
//!
//! Use the rotr-api crate to interact with this task.

#![no_std]
#![no_main]

use dice::{AliasData, CertData, HandoffData};
use idol_runtime::RequestError;
use lpc55_pac as device;
use ringbuf::{ringbuf, ringbuf_entry};
use task_rotr_api::RotrError;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    AliasMagic([u8; 16]),
    CertMagic([u8; 16]),
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

fn puf_ringbuf_stat(puf: &lpc55_pac::PUF) {
    if puf.stat.read().success().bit() {
        ringbuf_entry!(Trace::StatSuccess);
    }
    if puf.stat.read().error().bit() {
        ringbuf_entry!(Trace::StatError);
    }
    if puf.stat.read().busy().bit() {
        ringbuf_entry!(Trace::StatBusy);
    }
}

fn puf_ringbuf_ifstat(puf: &lpc55_pac::PUF) {
    if puf.ifstat.read().error().bit() {
        ringbuf_entry!(Trace::IfStatError);
    }
}

fn puf_ringbuf_allow(puf: &lpc55_pac::PUF) {
    if puf.allow.read().allowenroll().bit() {
        ringbuf_entry!(Trace::AllowEnroll);
    }
    if puf.allow.read().allowstart().bit() {
        ringbuf_entry!(Trace::AllowStart);
    }
    if puf.allow.read().allowsetkey().bit() {
        ringbuf_entry!(Trace::AllowSetKey);
    }
    if puf.allow.read().allowgetkey().bit() {
        ringbuf_entry!(Trace::AllowGetKey);
    }
}

// key index between 0 & 15
fn puf_set_key_index(puf: &lpc55_pac::PUF, index: u32) -> bool {
    if index > 15 {
        return false;
    }

    // SAFETY: The PAC interface can't prevent us from setting the reserved
    // bits (the top 28) so this interface is unsafe. We ensure safety by
    // using  the type system (index is an unsigned type) and check above.
    puf.keyindex.write(|w| unsafe { w.bits(index) });

    true
}

// size in bytes
fn puf_set_key_size(puf: &lpc55_pac::PUF, size: usize) -> bool {
    let size: u32 = ((size * 8) >> 6).try_into().unwrap();
    if size < 32 {
        // SAFETY: The PAC interface can't prevent us from setting the reserved
        // bits (the top 27) so this interface is unsafe. We ensure safety by
        // using  the type system (index is an unsigned type) and the check above.
        puf.keysize.write(|w| unsafe { w.bits(size) });

        true
    } else {
        return false;
    }
}

// wait for puf to accept last command submitted
fn puf_wait_for_cmd_accept(puf: &lpc55_pac::PUF) -> bool {
    // cmd has been accepted when:
    // - the PUF becomes busy or
    // - there's an error
    while !puf_is_busy(puf) && !puf_is_error(puf) {}

    // if there was an error the cmd was not accepted
    if !puf.stat.read().error().bit() {
        true
    } else {
        ringbuf_entry!(Trace::StatError);
        false
    }
}

fn puf_is_busy(puf: &lpc55_pac::PUF) -> bool {
    puf.stat.read().busy().bit()
}

fn puf_is_error(puf: &lpc55_pac::PUF) -> bool {
    puf.stat.read().error().bit()
}

fn puf_is_success(puf: &lpc55_pac::PUF) -> bool {
    puf.stat.read().success().bit()
}

// execute PUF GenerateKey command, keycode is returned through second param
// length in bytes
fn puf_genkey(
    puf: &lpc55_pac::PUF,
    length: usize,
    index: u32,
    keycode: &mut [u32; KEYCODE_LEN],
) -> bool {
    // GenerateKey can't be explicitly disallowed but it's covered by the
    // AllowSetKey.
    if !puf.allow.read().allowsetkey().bit() {
        panic!("DenySetKey");
    }

    // set parameters
    puf_set_key_size(puf, length);
    puf_set_key_index(puf, index);

    // execute GenerateKey function / set GENERATEKEY bit in CTRL register
    puf.ctrl.write(|w| w.generatekey().set_bit());
    if !puf_wait_for_cmd_accept(puf) {
        return false;
    }

    // while PUF is busy, read out whatever part of the KC is available
    let mut idx = 0;
    while puf_is_busy(puf) {
        if idx >= keycode.len() {
            ringbuf_entry!(Trace::IdxKeyCode);
            return false;
        }
        if puf.stat.read().codeoutavail().bit() {
            let keycode_part = puf.codeoutput.read().bits();
            keycode[idx] = keycode_part;
            idx += 1;
        }
    }

    puf_is_success(puf)
}

// execute PUF GetKey command, key is returned through third param
fn puf_getkey(
    puf: &lpc55_pac::PUF,
    keycode: &[u32; KEYCODE_LEN],
    key: &mut [u8; KEY_LEN],
) -> bool {
    if !puf.allow.read().allowgetkey().bit() {
        panic!("DenyGetKey");
    }

    // execute CTRL function / set GETKEY bit in CTRL register, no params
    puf.ctrl.write(|w| w.getkey().set_bit());
    ringbuf_entry!(Trace::GetKey);

    puf_wait_for_cmd_accept(puf);

    let mut kc_idx = 0;
    let mut key_idx = 0;
    // while PUF busy ... error detection?
    while puf_is_busy(puf) && !puf_is_error(puf) {
        if puf.stat.read().codeinreq().bit() {
            puf.codeinput.write(|w| unsafe { w.bits(keycode[kc_idx]) });
            kc_idx += 1;
        }
        if puf.stat.read().keyoutavail().bit() {
            for byte in puf.keyoutput.read().bits().to_ne_bytes() {
                key[key_idx] = byte;
                key_idx += 1;
            }
        }
    }

    ringbuf_entry!(Trace::KcIdx(kc_idx));
    ringbuf_entry!(Trace::KeyIdx(key_idx));

    puf_is_success(puf)
}

#[export_name = "main"]
fn main() -> ! {
    ringbuf_entry!(Trace::Startup);

    let cert_data = match CertData::from_mem() {
        Some(a) => a,
        None => panic!("CertData"),
    };

    ringbuf_entry!(Trace::CertMagic(cert_data.magic));

    let alias_data = match AliasData::from_mem() {
        Some(a) => a,
        None => panic!("AliasData"),
    };

    ringbuf_entry!(Trace::AliasMagic(alias_data.magic));

    let fwid = alias_data.alias_cert.get_fwid();
    ringbuf_entry!(Trace::Fwid(fwid.try_into().unwrap()));

    let peripherals = device::Peripherals::take().unwrap();
    let puf = peripherals.PUF;

    puf_ringbuf_stat(&puf);
    puf_ringbuf_ifstat(&puf);
    puf_ringbuf_allow(&puf);

    // generate key code
    let mut keycode = [0u32; KEYCODE_LEN];
    if puf_genkey(&puf, KEY_LEN, KEY_INDEX, &mut keycode) {
        ringbuf_entry!(Trace::KeyCode(keycode));
    } else {
        panic!("GenerageKeyFailed");
    }

    puf_ringbuf_stat(&puf);
    puf_ringbuf_ifstat(&puf);
    puf_ringbuf_allow(&puf);

    // get key from key code
    let mut key = [0u8; KEY_LEN];
    if puf_getkey(&puf, &keycode, &mut key) {
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
