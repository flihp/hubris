use crate::dice::SerialNumbers;
use core::ops::{Deref, Range};
use dice_crate::{
    CertData, CertSerialNumber, DeviceIdSerialMfg, DiceMfg, Handoff,
    SerialNumber, SizedBlob,
};
use hubpack::SerializedSize;
use lib_lpc55_usart::Usart;
use lpc55_pac::Peripherals;
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};
use static_assertions as sa;

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

fn gen_artifacts_from_mfg(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    usart_setup(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );

    let usart = Usart::from(peripherals.USART0.deref());
    let mfg_state = DeviceIdSerialMfg::new(&deviceid_keypair, usart).run();

    usart_teardown(
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

fn gen_artifacts_from_flash(handoff: &Handoff) -> SerialNumbers {
    let dice_state = DiceState::from_flash().expect("DiceState::from_flash");

    let cert_data =
        CertData::new(dice_state.deviceid_cert, dice_state.intermediate_cert);
    handoff.store(&cert_data);

    SerialNumbers {
        cert_serial_number: CertSerialNumber::default(),
        serial_number: dice_state.serial_number,
    }
}

pub fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
    if DiceState::is_programmed() {
        gen_artifacts_from_flash(handoff)
    } else {
        gen_artifacts_from_mfg(deviceid_keypair, peripherals, handoff)
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

pub fn usart_teardown(
    syscon: &lpc55_pac::syscon::RegisterBlock,
    iocon: &lpc55_pac::iocon::RegisterBlock,
    flexcomm: &lpc55_pac::flexcomm0::RegisterBlock,
) {
    gpio_teardown(syscon, iocon);
    flexcomm0_teardown(syscon, flexcomm);
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

fn gpio_teardown(
    syscon: &lpc55_pac::syscon::RegisterBlock,
    iocon: &lpc55_pac::iocon::RegisterBlock,
) {
    // IOCON: enable clock & reset
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().enable());
    syscon.presetctrl0.modify(|_, w| w.iocon_rst().released());

    // reset pin 29 and 30 to defaults
    iocon.pio0_29.reset();
    iocon.pio0_30.reset();

    syscon.presetctrl0.modify(|_, w| w.iocon_rst().asserted());
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().disable());

    syscon.presetctrl0.modify(|_, w| w.gpio0_rst().asserted());
    syscon.ahbclkctrl0.modify(|_, w| w.gpio0().disable());
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

fn flexcomm0_teardown(
    syscon: &lpc55_pac::syscon::RegisterBlock,
    flexcomm: &lpc55_pac::flexcomm0::RegisterBlock,
) {
    // set flexcomm0 clock to default (no clock)
    syscon.fcclksel0().modify(|_, w| w.sel().enum_0x7());

    // set flexcomm0 peripheral select to default
    flexcomm.pselid.write(|w| w.persel().no_periph_selected());

    syscon.presetctrl1.modify(|_, w| w.fc0_rst().asserted());
    syscon.ahbclkctrl1.modify(|_, w| w.fc0().disable());
}
