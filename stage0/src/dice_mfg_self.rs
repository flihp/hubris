// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::dice::SerialNumbers;
use crate::Handoff;
use core::mem;
use dice_crate::{
    Cert, CertData, DeviceIdCertBuilder, DiceMfg, PersistIdSeed, SeedBuf,
    SelfMfg, SizedBlob,
};
use lpc55_pac::Peripherals;
use lpc55_puf::Puf;
use salty::{constants::SECRETKEY_SEED_LENGTH, signature::Keypair};

// values for PUF parameters
const SEED_LEN: usize = SECRETKEY_SEED_LENGTH;
const KEYCODE_LEN: usize =
    Puf::key_to_keycode_len(SEED_LEN) / mem::size_of::<u32>();
const KEY_INDEX: u32 = 1;

pub fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    let puf = Puf::new(&peripherals.PUF);

    // Create key code for an ed25519 seed using the PUF. We use this seed
    // to generate a key used as an identity that is independent from the
    // DICE measured boot.
    let mut keycode = [0u32; KEYCODE_LEN];
    if !puf.generate_keycode(KEY_INDEX, SEED_LEN, &mut keycode) {
        panic!("failed to generate key code");
    }
    let keycode = keycode;

    // get keycode from DICE MFG flash region
    // good opportunity to put a magic value in the DICE MFG flash region
    let mut seed = [0u8; SEED_LEN];
    if !puf.get_key(&keycode, &mut seed) {
        panic!("failed to get ed25519 seed");
    }
    let seed = seed;

    let id_seed = PersistIdSeed::new(seed);

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
        SizedBlob::try_from(deviceid_cert.as_bytes()).unwrap(),
        mfg_state.persistid_cert,
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
