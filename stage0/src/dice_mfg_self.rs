// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::dice::SerialNumbers;
use crate::puf::{self, PersistIdSeed};
use dice_crate::{
    Cert, CertData, CertSerialNumber, DeviceIdCertBuilder, DiceMfg, Handoff,
    SeedBuf, SelfMfg, SizedBlob,
};
use lpc55_pac::Peripherals;
use salty::signature::Keypair;

pub fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    let keycode = puf::generate_seed(&peripherals.PUF);
    let id_seed = PersistIdSeed::from_key_code(&peripherals.PUF, &keycode);
    let id_keypair = Keypair::from(id_seed.as_bytes());

    // TODO: not a fan of this being mutable but it's necessary for us to
    // increment the cert serial number before creating the DeviceId.
    // Since the PersistId only issues a single cert (DeviceId) we could
    // just make the DeviceId cert serial number static ... or just make them
    // all static?
    let mut mfg_state = SelfMfg::new(&id_keypair).run();

    let deviceid_cert = DeviceIdCertBuilder::new(
        &mfg_state.cert_serial_number.next(),
        &mfg_state.serial_number,
        &deviceid_keypair.public,
    )
    .sign(&id_keypair);

    // transfer certs to CertData for serialization
    let cert_data = CertData::new(
        mfg_state.persistid_cert,
        SizedBlob::try_from(deviceid_cert.as_bytes()).unwrap(),
        mfg_state.intermediate_cert,
    );

    handoff.store(&cert_data);

    // Return new CertSerialNumber and platform serial number to caller.
    // These are used to fill in the templates for certs signed by the
    // DeviceId.
    SerialNumbers {
        cert_serial_number: Default::default(),
        serial_number: mfg_state.serial_number,
    }
}
