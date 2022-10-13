use crate::dice::SerialNumbers;
use dice_crate::{CertData, DeviceIdSelfMfg, DiceMfg, Handoff};
use lpc55_pac::Peripherals;
use salty::signature::Keypair;

pub fn gen_mfg_artifacts(
    deviceid_keypair: &Keypair,
    _peripherals: &Peripherals,
    handoff: &Handoff,
) -> SerialNumbers {
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
