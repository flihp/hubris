// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::image_header::Image;
use core::str::FromStr;
use dice_crate::{
    AliasCert, AliasHandoff, AliasOkm, Cdi, CdiL1, DeviceIdCert, DeviceIdOkm,
    Handoff, RngHandoff, RngSeed, SeedBuf, SerialNumber,
};
#[cfg(feature = "dice-mfg")]
use dice_crate::{Csr, Msg, Msgs};
#[cfg(feature = "dice-mfg")]
use lib_lpc55_usart::Usart;
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

// Poll the USART for lines (strings terminated by '\r'). If the line received
// is the string provided in 'term' (minus the '\r') the loop is terminated
// and true returned. If it doesn't, then it's written to the USART (echo'd
// back). All errors are ignored, false is never returned.
#[cfg(feature = "dice-mfg")]
fn echo_till_str(usart: &mut Usart, term: &str, buf: &mut [u8]) -> bool {
    if term.len() > buf.len() {
        return false;
    }

    loop {
        match usart.read_until(buf, &[b'\r']) {
            Ok(size) => {
                if &buf[..size - 1] == term.as_bytes() {
                    return true;
                }
                match usart.write_all(&buf[..size]) {
                    Ok(_) => buf.fill(0),
                    Err(_) => (),
                }
            }
            Err(_) => match usart.write_all("read error\n".as_bytes()) {
                Ok(_) => buf.fill(0),
                Err(_) => (),
            },
        }
    }
}

#[cfg(feature = "dice-mfg")]
fn gen_deviceid_csr(keypair: &Keypair, serial_number: &SerialNumber) -> Csr {
    let mut csr = Csr::new(serial_number.as_bytes());

    //TODO: error handling
    csr.sign(&keypair).expect("Failed to sign CSR.");

    csr
}

// Something with my serial setup / this usart causes errors the first time
// we use it. This function interacts with the usart and someone on the other
// side. It will echo back whatever is sent along with info about errors till
// the string 'deviceid' is received.
#[cfg(feature = "dice-mfg")]
fn usart_calibrate(usart: &mut Usart, buf: &mut [u8]) {
    let _ = usart.write_all("echo_till_str: \"deviceid\"\n>".as_bytes());
    echo_till_str(usart, "deviceid", buf);
}

// Send DeviceID CSR out over USART to MFG system for certification.
#[cfg(feature = "dice-mfg")]
fn certify_deviceid_mfg(csr: &Csr, peripherals: &Peripherals) -> Cert {
    let mut usart = Usart::turn_on(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
        &peripherals.USART0,
    );
    let mut buf = [0u8; Msg::MAX_ENCODED_SIZE];

    // sort out serial errors before doing mfg deviceid cert signing
    usart_calibrate(&mut usart, &mut buf);

    // wait for mfg system to request CSR
    let msg = match usart.read_until(&mut buf, &[0]) {
        Ok(size) => Msg::from(&buf[..size]),
        Err(_) => panic!("Failed to get CsrPlz"),
    };

    // check message type
    // TODO: make this a proper state machine
    match msg.msg {
        Msgs::CsrPlz => (),
        _ => panic!("Unexpected message: expected CsrPlz"),
    }

    buf.fill(0);

    let msg = Msg {
        id: msg.id + 1,
        msg: Msgs::Csr(*csr),
    };

    let size = msg.encode(&mut buf);

    // send CSR
    usart.write_all(&buf[..size]).expect("write_all?");
    buf.fill(0);

    // wait for response
    let msg = match usart.read_until(&mut buf, &[0]) {
        Ok(size) => Msg::from(&buf[..size]),
        Err(_) => panic!("Failed to get Cert"),
    };

    // check message type & extract cert
    let cert = match msg.msg {
        Msgs::Cert(cert) => cert,
        _ => panic!("Wrong message: expected Cert"),
    };

    Usart::turn_off(
        &peripherals.SYSCON,
        &peripherals.IOCON,
        &peripherals.FLEXCOMM0,
    );

    cert
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
    let peripherals = Peripherals::take().unwrap_lite();
    let handoff = Handoff::turn_on(&peripherals.SYSCON);

    let serial_number = get_serial_number();
    let deviceid_keypair = get_deviceid_keypair(&cdi);
    let mut cert_sn = 0;

    cfg_if::cfg_if! {
        if #[cfg(feature = "dice-mfg")] {
            let csr = gen_deviceid_csr(&deviceid_keypair, &serial_number);
            let deviceid_cert = certify_deviceid_mfg(&csr, &peripherals);
        } else {
            let deviceid_cert = DeviceIdCert::new()
                .set_serial_number(cert_sn)
                .set_issuer_sn(&serial_number)
                .set_subject_sn(&serial_number)
                .set_pub(&deviceid_keypair.public.as_bytes())
                .sign(&deviceid_keypair);
            cert_sn += 1;
        }
    }

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
