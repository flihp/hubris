// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::dice::SerialNumbers;
use crate::puf::{self, PersistIdSeed};
use dice_crate::{CertData, DiceMfg, Handoff, SeedBuf, SelfMfg};
use lpc55_pac::Peripherals;
use salty::signature::Keypair;

pub fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    let keycode = puf::generate_seed(&peripherals.PUF);
    let seed = puf::get_seed(&peripherals.PUF, &keycode);
    let id_seed = PersistIdSeed::new(seed);

    let id_keypair = Keypair::from(id_seed.as_bytes());

    let mfg_state = SelfMfg::new(&id_keypair).run();

    // TODO: generate DeviceId cert & stuff into CertData
    // transfer certs to CertData for serialization
    let cert_data =
        CertData::new(mfg_state.persistid_cert, mfg_state.intermediate_cert);

    handoff.store(&cert_data);

    // transfer platform and cert serial number to structure & return
    SerialNumbers {
        cert_serial_number: mfg_state.cert_serial_number,
        serial_number: mfg_state.serial_number,
    }
}
