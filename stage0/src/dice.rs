// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::image_header::Image;
use dice_crate::{
    AliasCertBuilder, AliasData, AliasOkm, Cdi, CdiL1, DeviceIdOkm,
    DiceMfgRunner, Handoff, SeedBuf, SwdspCertBuilder,
    SwdspData, SwdspOkm,
};
cfg_if::cfg_if! {
    if #[cfg(feature = "dice-mfg")] {
        use dice_crate::DeviceIdSelfMfg as DiceMfg;
    } else {
        use dice_crate::DiceSerialMfg as DiceMfg;
    }
}
use lpc55_pac::Peripherals;
use salty::signature::Keypair;
use sha3::{Digest, Sha3_256};
use unwrap_lite::UnwrapLite;

fn get_deviceid_keypair(cdi: &Cdi) -> Keypair {
    let devid_okm = DeviceIdOkm::from_cdi(cdi);

    Keypair::from(devid_okm.as_bytes())
}

pub fn run(image: &Image) {
    // Turn on the memory we're using to handoff DICE artifacts and create
    // type to interact with said memory. We turn this on unconditionally
    // if DICE is enabled so that hubris tasks will always get valid memory
    // even if it's all 0's.
    let syscon = Peripherals::take().unwrap_lite().SYSCON;
    let handoff = Handoff::turn_on(&syscon);

    let cdi = match Cdi::from_reg() {
        Some(cdi) => cdi,
        None => return,
    };

    let deviceid_keypair = get_deviceid_keypair(&cdi);

    // TODO: persistent storage
    let mut dice_state = DeviceIdSelfMfg::run(&deviceid_keypair);

    // Collect hash(es) of TCB. The first TCB Component Identifier (TCI)
    // calculated is the Hubris image. The DICE specs call this collection
    // of TCIs the FWID. This hash is stored in keeys certified by the
    // DeviceId. This hash should be 'updated' with relevant configuration
    // and code as FWID for Hubris becomes known.
    // TODO: This is a particularly naive way to calculate the FWID:
    // https://github.com/oxidecomputer/hubris/issues/736
    let mut fwid = Sha3_256::new();
    fwid.update(image.as_bytes());
    let fwid = fwid.finalize();

    // create CDI for layer 1 (L1) firmware (the hubris image we're booting)
    let cdi_l1 = CdiL1::new(&cdi, fwid.as_ref());

    // derive alias key
    let alias_okm = AliasOkm::from_cdi(&cdi_l1);
    let alias_keypair = Keypair::from(alias_okm.as_bytes());

    let alias_cert = AliasCertBuilder::new(
        &dice_state.cert_serial_number.next(),
        &dice_state.serial_number,
        &alias_keypair.public,
        fwid.as_ref(),
    )
    .sign(&deviceid_keypair);

    let alias_data =
        AliasData::new(alias_okm, alias_cert, dice_state.cert_chain.clone());

    handoff.store_alias(&alias_data);

    let swdsp_okm = SwdspOkm::from_cdi(&cdi_l1);
    let swdsp_keypair = Keypair::from(swdsp_okm.as_bytes());

    let swdsp_cert = SwdspCertBuilder::new(
        &dice_state.cert_serial_number.next(),
        &dice_state.serial_number,
        &swdsp_keypair.public,
        fwid.as_ref(),
    )
    .sign(&deviceid_keypair);

    let swdsp_data =
        SwdspData::new(swdsp_okm, swdsp_cert, dice_state.cert_chain.clone());

    handoff.store_swdsp(&swdsp_data);
}
