// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::cert::{DeviceIdSelfCert, DeviceIdSelfCertBuilder};
use crate::{CertSerialNumber, SerialNumber};
use core::str::FromStr;
use salty::signature::Keypair;

// data returned to caller
// typically required to use ECA post MFG this is
// this is what gets written to persistent storage after successful mfg
pub struct DiceState {
    pub cert_serial_number: CertSerialNumber,
    pub serial_number: SerialNumber,
    pub deviceid_cert: DeviceIdSelfCert,
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
            deviceid_cert,
        }
    }
}

// TODO: get the legit SN from somewhere
// https://github.com/oxidecomputer/hubris/issues/734
fn get_serial_number() -> SerialNumber {
    SerialNumber::from_str("0123456789ab").expect("SerialNumber::from_str")
}
