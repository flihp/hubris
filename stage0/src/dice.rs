// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::image_header::Image;
use core::str::FromStr;
use dice_crate::{
    AliasCert, AliasHandoff, AliasOkm, Cdi, CdiL1, DeviceIdCert, DeviceIdOkm,
    Handoff, RngHandoff, RngSeed, SeedBuf, SerialNumber,
};
use lpc55_pac::Peripherals;
use salty::signature::Keypair;
use sha3::{Digest, Sha3_256};
use unwrap_lite::UnwrapLite;

fn get_deviceid_keypair(cdi: &Cdi) -> Keypair {
    let devid_okm = DeviceIdOkm::from_cdi(cdi);

    Keypair::from(devid_okm.as_bytes())
}

fn get_serial_number() -> SerialNumber {
    // get serial number from somewhere
    SerialNumber::from_str("0123456789ab").expect("SerialNumber::from_str")
}

pub fn run(image: &Image) {
    // get deviceid keypair
    let cdi = match Cdi::new() {
        Some(cdi) => cdi,
        None => panic!("no CDI -> no DICE"),
    };

    if !Cdi::is_reg_clear() {
        panic!("CDI register not clear after read");
    }

    // Turn on the memory we're using to handoff DICE artifacts and create
    // type to interact with said memory.
    let syscon = Peripherals::take().unwrap_lite().SYSCON;
    let handoff = Handoff::turn_on(&syscon);

    let serial_number = get_serial_number();
    let deviceid_keypair = get_deviceid_keypair(&cdi);
    let mut cert_sn = 0;

    let deviceid_cert = DeviceIdCert::new()
        .set_serial_number(cert_sn)
        .set_issuer_sn(&serial_number)
        .set_subject_sn(&serial_number)
        .set_pub(&deviceid_keypair.public.as_bytes())
        .sign(&deviceid_keypair);
    cert_sn += 1;

    // Collect hash(es) of TCB. The first TCB Component Identifier (TCI)
    // calculated is the Hubris image. The DICE specs call this collection
    // of TCIs the FWID. This hash is stored in keeys certified by the
    // DeviceId. This hash should be 'updated' with relevant configuration
    // and code as FWID for Hubris becomes known.
    let mut fwid = Sha3_256::new();
    fwid.update(image.as_bytes());
    let fwid = fwid.finalize();

    // create CDI for layer 1 (L1) firmware (the hubris image we're booting)
    let cdi_l1 = CdiL1::new(&cdi, fwid.as_ref());

    // derive alias key
    // keys derived from CDI_L1 here must use HKDF w/ CDI_L1 as IKM & no salt
    // in extract, info string in expand.
    let alias_okm = AliasOkm::from_cdi(&cdi_l1);
    let alias_keypair = Keypair::from(alias_okm.as_bytes());

    // create AliasCert
    let alias_cert = AliasCert::new()
        .set_serial_number(cert_sn)
        .set_issuer_sn(&serial_number)
        .set_subject_sn(&serial_number)
        .set_pub(&alias_keypair.public.as_bytes())
        .set_fwid(fwid.as_ref())
        .sign(&deviceid_keypair);

    let alias_handoff = AliasHandoff {
        seed: alias_okm,
        alias_cert,
        deviceid_cert,
    };

    handoff.alias(&alias_handoff);

    let seed = RngSeed::from_cdi(&cdi);
    let rng_handoff = RngHandoff {
        serial_number,
        seed,
    };

    handoff.rng(&rng_handoff);

    // CDI_L1 is passed to whatever task owns SWD connection to SP
}
