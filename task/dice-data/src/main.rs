// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use dice::{AliasData, Cert, SeedBuf};
use ringbuf::{ringbuf, ringbuf_entry};
use salty::{
    constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH},
    signature::{Keypair, Signature},
    PublicKey,
};
use userlib::{hl, UnwrapLite};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Trace {
    PubCheck(bool),
    AliasSigCheck(bool),
    DeviceIdSigCheck(bool),
    Fwid([u8; 32]),
    AllChecksPassed,
    NoDice,
    None,
}

ringbuf!(Trace, 16, Trace::None);

#[export_name = "main"]
fn main() -> ! {
    let ticks = 1000u64;
    let alias_data = match AliasData::from_mem() {
        Some(alias_data) => alias_data,
        None => {
            ringbuf_entry!(Trace::NoDice);
            loop {
                hl::sleep_for(ticks);
            }
        },
    };
    let alias_cert = alias_data.alias_cert;
    let alias_keypair = Keypair::from(alias_data.seed.as_bytes());

    // ensure alias keypair derived from the provided seed has the same
    // public key as the cert
    if alias_cert.get_pub() == alias_keypair.public.as_bytes() {
        ringbuf_entry!(Trace::PubCheck(true));
    } else {
        ringbuf_entry!(Trace::PubCheck(false));
        panic!();
    }

    let deviceid_cert = alias_data.deviceid_cert;
    let data = alias_cert.get_signdata();
    let sig: &[u8; SIGNATURE_SERIALIZED_LENGTH] =
        alias_cert.get_sig().try_into().unwrap_lite();
    let sig: Signature = sig.into();
    let deviceid_pub: &[u8; PUBLICKEY_SERIALIZED_LENGTH] =
        deviceid_cert.get_pub().try_into().unwrap_lite();
    let deviceid_pub: PublicKey = deviceid_pub.try_into().unwrap_lite();

    // check that alias cert was signed by device id key
    if deviceid_pub.verify(data, &sig).is_ok() {
        ringbuf_entry!(Trace::AliasSigCheck(true));
    } else {
        ringbuf_entry!(Trace::AliasSigCheck(false));
        panic!();
    }

    // check that device id cert was signed by device id key (self signed)
    let data = deviceid_cert.get_signdata();
    let sig: &[u8; SIGNATURE_SERIALIZED_LENGTH] =
        deviceid_cert.get_sig().try_into().unwrap_lite();
    let sig: Signature = sig.into();
    if deviceid_pub.verify(data, &sig).is_ok() {
        ringbuf_entry!(Trace::DeviceIdSigCheck(true));
    } else {
        ringbuf_entry!(Trace::DeviceIdSigCheck(false));
        panic!();
    }

    // dump FWID to ringbuf for external verification
    let fwid = alias_cert.get_fwid();
    ringbuf_entry!(Trace::Fwid(*fwid));

    // if we've made it this far signatures on the DICE certs successfully
    // chain back to the root CA: the self-signed DeviceId cert in this case
    ringbuf_entry!(Trace::AllChecksPassed);

    loop {
        hl::sleep_for(ticks);
    }
}
