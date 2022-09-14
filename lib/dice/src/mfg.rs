// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::cert::{DeviceIdSelfCert, DeviceIdSelfCertBuilder};
use crate::{CertSerialNumber, SerialNumber};
use core::str::FromStr;
use salty::signature::Keypair;

// data returned to caller by MFG
// typically required to use ECA post MFG
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
        // TODO: non-self-signed certs will need real SNs
        // https://github.com/oxidecomputer/hubris/issues/734
        let dname_sn =
            SerialNumber::from_str("0123456789ab").expect("DeviceIdSelf SN");

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
