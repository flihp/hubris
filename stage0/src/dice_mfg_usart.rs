// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::dice::{MfgResult, KEYCODE_LEN, KEY_INDEX, SEED_LEN};
use core::ops::Deref;
use dice_crate::{
    CertSerialNumber, DiceMfg, PersistIdSeed, SeedBuf, SerialMfg, SerialNumber,
    SizedBlob,
};
use hubpack::SerializedSize;
use lib_lpc55_usart::Usart;
use lpc55_pac::Peripherals;
use lpc55_puf::Puf;
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};
use static_assertions as sa;

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

#[derive(Debug, PartialEq)]
pub enum DiceStateError {
    Deserialize,
    Serialize,
}

/// data received from manufacturing process
/// serialized to flash after mfg as device identity
#[derive(Deserialize, Serialize, SerializedSize)]
struct DiceState {
    pub persistid_key_code: [u32; KEYCODE_LEN],
    pub serial_number: SerialNumber,
    pub persistid_cert: SizedBlob,
    pub intermediate_cert: SizedBlob,
}

impl DiceState {
    fn from_flash() -> Result<Self, DiceStateError> {
        // SAFETY: This unsafe block relies on the caller verifying that the
        // flash region being read has been programmed. We verify this in the
        // conditional evaluated before executing this unsafe code.
        let src = unsafe {
            core::slice::from_raw_parts(
                DICE_FLASH.start as *const u8,
                DiceState::MAX_SIZE,
            )
        };

        let (state, _) = hubpack::deserialize::<Self>(src)
            .map_err(|_| DiceStateError::Deserialize)?;

        Ok(state)
    }

    pub fn to_flash(&self) -> Result<usize, DiceStateError> {
        let mut buf = [0u8; flash_page_align!(Self::MAX_SIZE)];

        let size = hubpack::serialize(&mut buf, self)
            .map_err(|_| DiceStateError::Serialize)?;

        // SAFETY: This unsafe block relies on the caller verifying that the
        // flash region being programmed is correctly aligned and sufficiently
        // large to hold Self::MAX bytes. We do this by static assertion.
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

/// Generate platform identity key from PUF and manufacture the system
/// by certifying this identity. The certification process uses the usart
/// peripheral to exchange manufacturing data, CSR & cert with the
/// manufacturing line.
fn gen_artifacts_from_mfg(peripherals: &Peripherals) -> MfgResult {
    let puf = Puf::new(&peripherals.PUF);

    // If key index is blocked the PUF won't produce an error when we
    // generate or get the key but it will return a key that's all 0's.
    // To prevent this we check that the key index is not blocked before
    // we get our key.
    if puf.is_index_blocked(KEY_INDEX) {
        panic!("key index blocked");
    }

    // Create key code for an ed25519 seed using the PUF. We use this seed
    // to generate a key used as an identity that is independent from the
    // DICE measured boot.
    let mut id_keycode = [0u32; KEYCODE_LEN];
    if !puf.generate_keycode(KEY_INDEX, SEED_LEN, &mut id_keycode) {
        panic!("failed to generate key code");
    }
    let id_keycode = id_keycode;

    // get keycode from DICE MFG flash region
    // good opportunity to put a magic value in the DICE MFG flash region
    let mut seed = [0u8; SEED_LEN];
    if !puf.get_key(&id_keycode, &mut seed) {
        panic!("failed to get ed25519 seed");
    }
    let seed = seed;

    // we're done with the puf: block the key index used for the identity
    // key and lock the block register
    if !puf.block_index(KEY_INDEX) {
        panic!("failed to block PUF index");
    }
    puf.lock_indices_low();

    let id_seed = PersistIdSeed::new(seed);

    let id_keypair = Keypair::from(id_seed.as_bytes());

    usart_setup(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );

    let usart = Usart::from(peripherals.USART0.deref());

    let dice_data = SerialMfg::new(&id_keypair, usart).run();

    let dice_state = DiceState {
        persistid_key_code: id_keycode,
        serial_number: dice_data.serial_number,
        persistid_cert: dice_data.persistid_cert,
        intermediate_cert: dice_data.intermediate_cert,
    };

    dice_state.to_flash().unwrap();

    MfgResult {
        cert_serial_number: Default::default(),
        serial_number: dice_state.serial_number,
        persistid_keypair: id_keypair,
        persistid_cert: dice_state.persistid_cert,
        intermediate_cert: dice_state.intermediate_cert,
    }
}

/// Get platform identity data from the DICE flash region. This is the data
/// we get from the 'gen_artifacts_from_mfg' function.
fn gen_artifacts_from_flash(peripherals: &Peripherals) -> MfgResult {
    let dice_state = DiceState::from_flash().expect("DiceState::from_flash");

    let puf = Puf::new(&peripherals.PUF);

    // If key index is blocked the PUF won't produce an error when we
    // generate or get the key but it will return a key that's all 0's.
    // To prevent this we check that the key index is not blocked before
    // we get our key.
    if puf.is_index_blocked(KEY_INDEX) {
        panic!("key index blocked");
    }

    // get keycode from DICE MFG flash region
    let mut seed = [0u8; SEED_LEN];
    if !puf.get_key(&dice_state.persistid_key_code, &mut seed) {
        panic!("failed to get ed25519 seed");
    }
    let seed = seed;

    // we're done with the puf: block the key index used for the identity
    // key and lock the block register
    if !puf.block_index(KEY_INDEX) {
        panic!("failed to block PUF index");
    }
    puf.lock_indices_low();

    let id_seed = PersistIdSeed::new(seed);

    let id_keypair = Keypair::from(id_seed.as_bytes());

    MfgResult {
        cert_serial_number: CertSerialNumber::default(),
        serial_number: dice_state.serial_number,
        persistid_keypair: id_keypair,
        persistid_cert: dice_state.persistid_cert,
        intermediate_cert: dice_state.intermediate_cert,
    }
}

pub fn gen_mfg_artifacts_usart(peripherals: &Peripherals) -> MfgResult {
    if DiceState::is_programmed() {
        gen_artifacts_from_flash(peripherals)
    } else {
        gen_artifacts_from_mfg(peripherals)
    }
}

pub fn usart_setup(
    syscon: &lpc55_pac::syscon::RegisterBlock,
    iocon: &lpc55_pac::iocon::RegisterBlock,
    flexcomm: &lpc55_pac::flexcomm0::RegisterBlock,
) {
    gpio_setup(syscon, iocon);
    flexcomm0_setup(syscon, flexcomm);
}

/// Configure GPIO pin 29 & 30 for RX & TX respectively, as well as
/// digital mode.
fn gpio_setup(
    syscon: &lpc55_pac::syscon::RegisterBlock,
    iocon: &lpc55_pac::iocon::RegisterBlock,
) {
    // IOCON: enable clock & reset
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().enable());
    syscon.presetctrl0.modify(|_, w| w.iocon_rst().released());

    // GPIO: enable clock & reset
    syscon.ahbclkctrl0.modify(|_, w| w.gpio0().enable());
    syscon.presetctrl0.modify(|_, w| w.gpio0_rst().released());

    // configure GPIO pin 29 & 30 for RX & TX respectively, as well as
    // digital mode
    iocon
        .pio0_29
        .write(|w| w.func().alt1().digimode().digital());
    iocon
        .pio0_30
        .write(|w| w.func().alt1().digimode().digital());

    // disable IOCON clock
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().disable());
}

fn flexcomm0_setup(
    syscon: &lpc55_pac::syscon::RegisterBlock,
    flexcomm: &lpc55_pac::flexcomm0::RegisterBlock,
) {
    syscon.ahbclkctrl1.modify(|_, w| w.fc0().enable());
    syscon.presetctrl1.modify(|_, w| w.fc0_rst().released());

    // Set flexcom to be a USART
    flexcomm.pselid.write(|w| w.persel().usart());

    // set flexcomm0 / uart clock to 12Mhz
    syscon.fcclksel0().modify(|_, w| w.sel().enum_0x2());
}

include!(concat!(env!("OUT_DIR"), "/dice-mfg.rs"));
