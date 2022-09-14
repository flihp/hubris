// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::cert::{Cert, DeviceIdSelfCertBuilder};
use crate::{CertSerialNumber, SerialNumber};
use core::str::FromStr;
use hubpack::SerializedSize;
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

const CERT_BLOB_SIZE: usize = 1024;

#[derive(Clone, Deserialize, Serialize, SerializedSize)]
pub struct CertBlob(#[serde(with = "BigArray")] [u8; CERT_BLOB_SIZE]);

impl Default for CertBlob {
    fn default() -> Self {
        Self([0u8; CERT_BLOB_SIZE])
    }
}

// we'd get this for free if 'Certs' implemented Copy
// but last time I did that I copied unknowningly and bloated things horribly
// this interface is an explicit copy
// alternatively the DeviceId cert could be a CertBlob from the "get go"?
impl<T: Cert> From<T> for CertBlob {
    fn from(t: T) -> Self {
        let mut buf = [0u8; CERT_BLOB_SIZE];

        let bytes = t.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);

        Self(buf)
    }
}

#[derive(Clone, Deserialize, Serialize, SerializedSize)]
pub struct CertChain {
    pub device_id: CertBlob,
    pub intermediate: CertBlob,
}

// data returned to caller
// typically required to use ECA post MFG this is
// this is what gets written to persistent storage after successful mfg
pub struct DiceState {
    pub cert_serial_number: CertSerialNumber,
    pub serial_number: SerialNumber,
    pub cert_chain: CertChain,
}

// Trait defining our interface to the "manufacturing process".
pub trait DiceMfgRunner {
    fn run(keypair: &Keypair) -> DiceState;
}

pub struct DeviceIdSelfMfg;

impl DiceMfgRunner for DeviceIdSelfMfg {
    fn run(keypair: &Keypair) -> DiceState {
        let mut cert_sn: CertSerialNumber = Default::default();
        let dname_sn = get_serial_number();

        let deviceid_cert = DeviceIdSelfCertBuilder::new(
            &cert_sn.next(),
            &dname_sn,
            &keypair.public,
        )
        .sign(&keypair);

        DiceState {
            cert_serial_number: cert_sn,
            serial_number: dname_sn,
            cert_chain: CertChain {
                device_id: CertBlob::from(deviceid_cert),
                intermediate: CertBlob::default(),
            }
        }
    }
}

pub struct DiceSerialMfg;

impl DiceMfgRunner for DiceSerialMfg {
    fn run(keypair: &Keypair) -> DiceState {
        // TODO
    }
}

// TODO: get the legit SN from somewhere
// https://github.com/oxidecomputer/hubris/issues/734
fn get_serial_number() -> SerialNumber {
    SerialNumber::from_str("0123456789ab").expect("SerialNumber::from_str")
}
