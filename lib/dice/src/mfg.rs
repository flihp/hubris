// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    cert::{Cert, DeviceIdSelfCertBuilder},
    CertSerialNumber,
};
use dice_mfg_msgs::{SerialNumber, SizedBlob};
use lib_lpc55_usart::Usart;
use salty::signature::Keypair;

// data returned to caller by MFG
// typically required to use ECA post MFG
// this is what gets written to persistent storage after successful mfg
pub struct DiceMfgState {
    pub cert_serial_number: CertSerialNumber,
    pub serial_number: SerialNumber,
    pub deviceid_cert: SizedBlob,
    pub intermediate_cert: SizedBlob,
}

pub trait DiceMfg {
    fn run(self) -> DiceMfgState;
}

pub struct DeviceIdSelfMfg<'a> {
    keypair: &'a Keypair,
}

impl<'a> DeviceIdSelfMfg<'a> {
    pub fn new(keypair: &'a Keypair) -> Self {
        Self { keypair }
    }
}

impl DiceMfg for DeviceIdSelfMfg<'_> {
    fn run(self) -> DiceMfgState {
        let mut cert_sn: CertSerialNumber = Default::default();
        let dname_sn =
            SerialNumber::try_from("0123456789ab").expect("DeviceIdSelf SN");

        let deviceid_cert = DeviceIdSelfCertBuilder::new(
            &cert_sn.next(),
            &dname_sn,
            &self.keypair.public,
        )
        .sign(self.keypair);

        DiceMfgState {
            cert_serial_number: cert_sn,
            serial_number: dname_sn,
            // TODO: static assert deviceid_cert size < SizedBuf max
            deviceid_cert: SizedBlob::try_from(deviceid_cert.as_bytes())
                .expect("deviceid cert to SizedBlob"),
            intermediate_cert: SizedBlob::default(),
        }
    }
}

pub struct DeviceIdSerialMfg<'a> {
    keypair: &'a Keypair,
    _usart: Usart<'a>,
}

impl<'a> DeviceIdSerialMfg<'a> {
    pub fn new(keypair: &'a Keypair, usart: Usart<'a>) -> Self {
        Self {
            keypair,
            _usart: usart,
        }
    }
}

impl DiceMfg for DeviceIdSerialMfg<'_> {
    fn run(self) -> DiceMfgState {
        // produce self-signed cert till mfg commands land
        let mut cert_sn: CertSerialNumber = Default::default();
        let dname_sn =
            SerialNumber::try_from("0123456789ab").expect("DeviceIdSelf SN");

        let deviceid_cert = DeviceIdSelfCertBuilder::new(
            &cert_sn.next(),
            &dname_sn,
            &self.keypair.public,
        )
        .sign(self.keypair);

        DiceMfgState {
            cert_serial_number: cert_sn,
            serial_number: dname_sn,
            deviceid_cert: SizedBlob::try_from(deviceid_cert.as_bytes())
                .expect("deviceid cert to SizedBlob"),
            intermediate_cert: SizedBlob::default(),
        }
    }
}
