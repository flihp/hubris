// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::image_header::Image;
use core::{
    convert::{TryFrom, TryInto},
    ops::Range,
};
use dice_crate::{
    AliasCertBuilder, AliasData, AliasOkm, Cdi, CdiL1, CertData,
    CertSerialNumber, DeviceIdOkm, DiceMfg, Handoff, RngData, RngSeed, SeedBuf,
    SerialNumber, SizedBlob, SpMeasureCertBuilder, SpMeasureData, SpMeasureOkm,
    TrustQuorumDheCertBuilder, TrustQuorumDheOkm,
};
use hubpack::SerializedSize;
use lpc55_pac::Peripherals;
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};
//use serde_big_array::BigArray;
use sha3::{Digest, Sha3_256};
use static_assertions as sa;
use unwrap_lite::UnwrapLite;

// Take first 2k from RoT persistent area defined in RFD 108
// https://rfd.shared.oxide.computer/rfd/0108#_flash_layout
// TODO: get from memory map / memory.toml at build time
const DICE_FLASH: Range<usize> = 0x9_0000..0x9_0800;

macro_rules! flash_page_align {
    ($size:expr) => {
        if $size % lpc55_romapi::FLASH_PAGE_SIZE != 0 {
            ($size & !(lpc55_romapi::FLASH_PAGE_SIZE - 1))
                + lpc55_romapi::FLASH_PAGE_SIZE
        } else {
            $size
        }
    };
}

// ensure DiceState object will fit in DICE_FLASH range
sa::const_assert!(
    (DICE_FLASH.end - DICE_FLASH.start)
        >= flash_page_align!(DiceState::MAX_SIZE)
);

// ensure DICE_FLASH start and end are alligned
sa::const_assert!(DICE_FLASH.end % lpc55_romapi::FLASH_PAGE_SIZE == 0);
sa::const_assert!(DICE_FLASH.start % lpc55_romapi::FLASH_PAGE_SIZE == 0);

struct SerialNumbers {
    cert_serial_number: CertSerialNumber,
    serial_number: SerialNumber,
}

#[derive(Debug, PartialEq)]
pub enum DiceStateError {
    Deserialize,
    Serialize,
}

/// data received from manufacturing process
/// serialized to flash after mfg as device identity
#[derive(Deserialize, Serialize, SerializedSize)]
struct DiceState {
    pub serial_number: SerialNumber,
    pub deviceid_cert: SizedBlob,
    pub intermediate_cert: SizedBlob,
}

impl TryFrom<&[u8]> for DiceState {
    type Error = DiceStateError;

    // from flash? include raw memory address transform into slice too?
    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let (state, _) = hubpack::deserialize::<Self>(s)
            .map_err(|_| DiceStateError::Deserialize)?;

        Ok(state)
    }
}

#[cfg(feature = "dice-mfg")]
impl DiceState {
    pub fn to_flash(&self) -> Result<usize, DiceStateError> {
        let mut buf = [0u8; flash_page_align!(Self::MAX_SIZE)];

        let size = hubpack::serialize(&mut buf, self)
            .map_err(|_| DiceStateError::Serialize)?;

        // SAFETY: This unsafe block relies on the caller verifying that the flash region being
        // programmed is correctly aligned and sufficiently large to hold Self::MAX bytes. We do
        // this by static assertion.
        // TODO: error handling
        unsafe {
            lpc55_romapi::flash_erase(
                DICE_FLASH.start as *const u32 as u32,
                flash_page_align!(Self::MAX_SIZE) as u32,
            )
            .expect("flash_erase");
            lpc55_romapi::flash_write(
                DICE_FLASH.start as *const u32 as u32,
                &mut buf as *mut u8,
                flash_page_align!(Self::MAX_SIZE) as u32,
            )
            .expect("flash_write");
        }

        Ok(size)
    }

    pub fn is_programmed() -> bool {
        lpc55_romapi::validate_programmed(
            DICE_FLASH.start as u32,
            flash_page_align!(Self::MAX_SIZE) as u32,
        )
    }
}

#[cfg(feature = "dice-mfg")]
fn gen_artifacts_from_mfg(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    use crate::usart;
    use core::ops::Deref;
    use dice_crate::DeviceIdSerialMfg;
    use lib_lpc55_usart::Usart;

    usart::setup(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );

    let usart = Usart::from(peripherals.USART0.deref());
    let mfg_state = DeviceIdSerialMfg::new(&deviceid_keypair, usart).run();

    usart::teardown(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );

    let dice_state = DiceState {
        deviceid_cert: mfg_state.deviceid_cert,
        intermediate_cert: mfg_state.intermediate_cert,
        serial_number: mfg_state.serial_number,
    };
    dice_state.to_flash().expect("DiceState::to_flash");

    let cert_data =
        CertData::new(dice_state.deviceid_cert, dice_state.intermediate_cert);
    handoff.store(&cert_data);

    SerialNumbers {
        cert_serial_number: mfg_state.cert_serial_number,
        serial_number: mfg_state.serial_number,
    }
}

#[cfg(feature = "dice-mfg")]
fn gen_artifacts_from_flash(handoff: &Handoff) -> SerialNumbers {
    let dice_state = DiceState::try_from(src).expect("deserialize DiceState");

    let cert_data =
        CertData::new(dice_state.deviceid_cert, dice_state.intermediate_cert);
    handoff.store(&cert_data);

    SerialNumbers {
        cert_serial_number: CertSerialNumber::default(),
        serial_number: dice_state.serial_number,
    }
}

#[cfg(feature = "dice-mfg")]
fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    if DiceState::is_programmed() {
        // SAFETY: This unsafe block relies on the caller verifying that the
        // flash region being read has been programmed. We verify this in the
        // conditional evaluated before executing this unsafe code.
        let src = unsafe {
            core::slice::from_raw_parts(
                DICE_FLASH.start as *const u8,
                DiceState::MAX_SIZE,
            )
        };

        gen_artifacts_from_flash(handoff)
    } else {
        gen_artifacts_from_mfg(deviceid_keypair, peripherals, handoff)
    }
}

#[cfg(feature = "dice-self")]
fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    _peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    use dice_crate::DeviceIdSelfMfg;

    let mfg_state = DeviceIdSelfMfg::new(&deviceid_keypair).run();

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

fn gen_deviceid_keypair(cdi: &Cdi) -> Keypair {
    let devid_okm = DeviceIdOkm::from_cdi(cdi);

    Keypair::from(devid_okm.as_bytes())
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

    let mut serial_numbers =
        gen_mfg_artifacts(&deviceid_keypair, &peripherals, &handoff);

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
