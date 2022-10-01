// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::image_header::Image;
use core::convert::TryInto;
use dice_crate::{
    AliasCertBuilder, AliasData, AliasOkm, Cdi, CdiL1, CertData,
    CertSerialNumber, DeviceIdOkm, DiceMfg, Handoff, RngData, RngSeed, SeedBuf,
    SerialNumber, SpMeasureCertBuilder, SpMeasureData, SpMeasureOkm,
    TrustQuorumDheCertBuilder, TrustQuorumDheOkm,
};
use lpc55_pac::Peripherals;
use salty::signature::Keypair;
use sha3::{Digest, Sha3_256};
use unwrap_lite::UnwrapLite;

#[cfg(feature = "dice-self")]
use dice_crate::DeviceIdSelfMfg;
#[cfg(feature = "dice-mfg")]
use dice_crate::DeviceIdSerialMfg;

fn gen_deviceid_keypair(cdi: &Cdi) -> Keypair {
    let devid_okm = DeviceIdOkm::from_cdi(cdi);

    Keypair::from(devid_okm.as_bytes())
}

struct SerialNumbers {
    cert_serial_number: CertSerialNumber,
    serial_number: SerialNumber,
}

#[cfg(feature = "dice-mfg")]
fn setup_serial_mfg<'a>(
    keypair: &'a Keypair,
    peripherals: &'a Peripherals,
) -> DeviceIdSerialMfg<'a> {
    use crate::usart;
    use core::ops::Deref;
    use lib_lpc55_usart::Usart;

    // if dice_state already in flash, extract & return
    usart::setup(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );

    let usart = Usart::from(peripherals.USART0.deref());
    DeviceIdSerialMfg::new(&keypair, usart)
}

#[cfg(feature = "dice-mfg")]
fn teardown_serial_mfg(peripherals: &Peripherals) {
    use crate::usart;

    usart::teardown(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );
}

fn gen_mfg_artifacts<T: DiceMfg>(mfg: T, handoff: &Handoff) -> SerialNumbers {
    let mfg_state = mfg.run();

    // transfer certs to CertData for serialization
    let cert_data =
        CertData::new(mfg_state.deviceid_cert, mfg_state.intermediate_cert);

    handoff.store(&cert_data);

    // transfer platform and cert serial number to structure & return
    SerialNumbers {
        cert_serial_number: mfg_state.cert_serial_number,
        serial_number: mfg_state.serial_number,
    }
}

fn gen_alias_artifacts(
    cdi_l1: &CdiL1,
    cert_serial_number: &mut CertSerialNumber,
    serial_number: &SerialNumber,
    deviceid_keypair: &Keypair,
    fwid: &[u8; 32],
    handoff: &Handoff,
) {
    let alias_okm = AliasOkm::from_cdi(&cdi_l1);
    let alias_keypair = Keypair::from(alias_okm.as_bytes());

    let alias_cert = AliasCertBuilder::new(
        &cert_serial_number.next(),
        &serial_number,
        &alias_keypair.public,
        fwid,
    )
    .sign(&deviceid_keypair);

    let tqdhe_okm = TrustQuorumDheOkm::from_cdi(&cdi_l1);
    let tqdhe_keypair = Keypair::from(tqdhe_okm.as_bytes());

    let tqdhe_cert = TrustQuorumDheCertBuilder::new(
        &cert_serial_number.next(),
        &serial_number,
        &tqdhe_keypair.public,
        fwid,
    )
    .sign(&deviceid_keypair);

    let alias_data =
        AliasData::new(alias_okm, alias_cert, tqdhe_okm, tqdhe_cert);

    handoff.store(&alias_data);
}

fn gen_spmeasure_artifacts(
    cdi_l1: &CdiL1,
    cert_serial_number: &mut CertSerialNumber,
    serial_number: &SerialNumber,
    deviceid_keypair: &Keypair,
    fwid: &[u8; 32],
    handoff: &Handoff,
) {
    let spmeasure_okm = SpMeasureOkm::from_cdi(&cdi_l1);
    let spmeasure_keypair = Keypair::from(spmeasure_okm.as_bytes());

    let spmeasure_cert = SpMeasureCertBuilder::new(
        &cert_serial_number.next(),
        &serial_number,
        &spmeasure_keypair.public,
        fwid,
    )
    .sign(&deviceid_keypair);

    let spmeasure_data = SpMeasureData::new(spmeasure_okm, spmeasure_cert);

    handoff.store(&spmeasure_data);
}

fn gen_rng_artifacts(cdi_l1: &CdiL1, handoff: &Handoff) {
    let rng_seed = RngSeed::from_cdi(cdi_l1);
    let rng_data = RngData::new(rng_seed);

    handoff.store(&rng_data);
}

fn gen_fwid(image: &Image) -> [u8; 32] {
    // Collect hash(es) of TCB. The first TCB Component Identifier (TCI)
    // calculated is the Hubris image. The DICE specs call this collection
    // of TCIs the FWID. This hash is stored in keeys certified by the
    // DeviceId. This hash should be 'updated' with relevant configuration
    // and code as FWID for Hubris becomes known.
    // TODO: This is a particularly naive way to calculate the FWID:
    // https://github.com/oxidecomputer/hubris/issues/736
    let mut fwid = Sha3_256::new();
    fwid.update(image.as_bytes());

    fwid.finalize().try_into().expect("fwid")
}

pub fn run(image: &Image) {
    // Turn on the memory we're using to handoff DICE artifacts and create
    // type to interact with said memory. We turn this on unconditionally
    // if DICE is enabled so that hubris tasks will always get valid memory
    // even if it's all 0's.
    let peripherals = Peripherals::take().unwrap_lite();
    let handoff = Handoff::turn_on(&peripherals.SYSCON);

    let cdi = match Cdi::from_reg() {
        Some(cdi) => cdi,
        None => return,
    };

    let deviceid_keypair = gen_deviceid_keypair(&cdi);

    #[cfg(feature = "dice-mfg")]
    let mfg = setup_serial_mfg(&deviceid_keypair, &peripherals);

    #[cfg(feature = "dice-self")]
    let mfg = DeviceIdSelfMfg::new(&deviceid_keypair);

    let mut serial_numbers = gen_mfg_artifacts(mfg, &handoff);

    #[cfg(feature = "dice-mfg")]
    teardown_serial_mfg(&peripherals);

    let fwid = gen_fwid(image);

    // create CDI for layer 1 (L1) firmware (the hubris image we're booting)
    let cdi_l1 = CdiL1::new(&cdi, &fwid);

    gen_alias_artifacts(
        &cdi_l1,
        &mut serial_numbers.cert_serial_number,
        &serial_numbers.serial_number,
        &deviceid_keypair,
        &fwid,
        &handoff,
    );

    gen_spmeasure_artifacts(
        &cdi_l1,
        &mut serial_numbers.cert_serial_number,
        &serial_numbers.serial_number,
        &deviceid_keypair,
        &fwid,
        &handoff,
    );

    gen_rng_artifacts(&cdi_l1, &handoff);
}
