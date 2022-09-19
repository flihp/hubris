// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::cert::{Cert, DeviceIdSelfCertBuilder};
use crate::{CertSerialNumber, SerialNumber};
use core::str::FromStr;
use hubpack::SerializedSize;
use lib_lpc55_usart::{Error, Read, Usart, Write};
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

const CERT_BLOB_SIZE: usize = 768;

#[derive(Clone, Deserialize, Serialize, SerializedSize)]
pub struct CertBlob(#[serde(with = "BigArray")] [u8; CERT_BLOB_SIZE]);

impl Default for CertBlob {
    fn default() -> Self {
        Self([0u8; CERT_BLOB_SIZE])
    }
}

// we'd get this for free if 'Certs' implemented Copy
// but last time I did that I copied unknowningly and bloated things horribly
// this interface is an explicit copy
// alternatively the DeviceId cert could be a CertBlob from the "get go"?
impl<T: Cert> From<T> for CertBlob {
    fn from(t: T) -> Self {
        let mut buf = [0u8; CERT_BLOB_SIZE];

        let bytes = t.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);

        Self(buf)
    }
}

#[derive(Clone, Deserialize, Serialize, SerializedSize)]
pub struct CertChain {
    pub device_id: CertBlob,
    pub intermediate: CertBlob,
}

// data returned to caller by MFG
// typically required to use ECA post MFG
// this is what gets written to persistent storage after successful mfg
pub struct DiceState {
    pub cert_serial_number: CertSerialNumber,
    pub serial_number: SerialNumber,
    pub cert_chain: CertChain,
}

pub struct DeviceIdSelfMfg;

impl DeviceIdSelfMfg {
    pub fn run(keypair: &Keypair) -> DiceState {
        let mut cert_sn: CertSerialNumber = Default::default();
        // TODO: non-self-signed certs will need real SNs
        // https://github.com/oxidecomputer/hubris/issues/734
        let dname_sn =
            SerialNumber::from_str("0123456789ab").expect("DeviceIdSelf SN");

        let deviceid_cert = DeviceIdSelfCertBuilder::new(
            &cert_sn.next(),
            &dname_sn,
            &keypair.public,
        )
        .sign(&keypair);

        DiceState {
            cert_serial_number: cert_sn,
            serial_number: dname_sn,
            cert_chain: CertChain {
                device_id: CertBlob::from(deviceid_cert),
                intermediate: CertBlob::default(),
            },
        }
    }
}

pub struct DeviceIdSerialMfg;

impl DeviceIdSerialMfg {
    pub fn run(_keypair: &Keypair, usart: &mut Usart) -> DiceState {
        let mut buf = [0u8; 128];
        calibrate(usart, &mut buf);

        // check for DiceState in persistent storage
        // if present return it, else continue mfging
        // wait for CanIHasCsr(SerialNumber)
        // send CSR
        // poll HeresYourCert(CertChain)

        let cert_chain = CertChain {
            device_id: CertBlob::default(),
            intermediate: CertBlob::default(),
        };

        // write CertChain to flash

        DiceState {
            cert_serial_number: CertSerialNumber::default(),
            serial_number: SerialNumber::from_str("0123456789ab").expect("SN"),
            cert_chain,
        }
    }
}

/// Write all bytes in buf to usart fifo, poll if fifo is full.
/// NOTE: This does not guarantee transmission of all bytes. See flush_all.
fn write_all(usart: &mut Usart, src: &[u8]) -> Result<(), Error> {
    for b in src {
        let mut done = false;
        while !done {
            done = match usart.write(*b) {
                Ok(_) => true,
                Err(nb::Error::WouldBlock) => false,
                Err(nb::Error::Other(e)) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Poll the usart reading all bytes into dst until a termination sequence
/// is encountered.
pub fn read_until(
    usart: &mut Usart,
    dst: &mut [u8],
    term: &[u8],
) -> Result<usize, Error> {
    if dst.is_empty() || term.is_empty() || term.len() > dst.len() {
        panic!("invalid dst or term");
    }
    let mut pos = 0;
    let mut done = false;
    while !done {
        done = match usart.read() {
            Ok(b) => {
                if pos > dst.len() - 1 {
                    return Err(Error::BufFull);
                }
                dst[pos] = b;
                pos += 1;
                // ensure we have at least as many bytes as the terminator
                if term.len() <= pos {
                    let mut done = true;
                    // not done till last term.len() bytes in dst are same
                    // as term
                    for (&b, &t) in
                        dst[..pos].iter().rev().zip(term.iter().rev())
                    {
                        if b != t {
                            done = false;
                        }
                    }
                    done
                } else {
                    false
                }
            }
            Err(nb::Error::WouldBlock) => false,
            Err(nb::Error::Other(e)) => return Err(e),
        }
    }
    Ok(pos)
}

/// Like 'flush' from embedded-hal 'Write' trait but polls till the transmit
/// FIFO is empty.
pub fn flush_all(usart: &mut Usart) {
    let mut done = false;
    while !done {
        done = match usart.flush() {
            Ok(_) => true,
            Err(nb::Error::WouldBlock) => false,
            Err(nb::Error::Other(_)) => false,
        }
    }
}

fn echo_till_str(usart: &mut Usart, term: &str, buf: &mut [u8]) -> bool {
    if term.len() > buf.len() {
        return false;
    }

    loop {
        match read_until(usart, buf, &[b'\r']) {
            Ok(size) => {
                if &buf[..size - 1] == term.as_bytes() {
                    return true;
                }
                match write_all(usart, &buf[..size]) {
                    Ok(_) => buf.fill(0),
                    Err(_) => (),
                }
            }
            Err(_) => match write_all(usart, "read error\n".as_bytes()) {
                Ok(_) => buf.fill(0),
                Err(_) => (),
            },
        }
    }
}

pub fn calibrate(usart: &mut Usart, buf: &mut [u8]) {
    let _ = write_all(usart, "echo_till_str: \"deviceid\"\n>".as_bytes());
    echo_till_str(usart, "deviceid", buf);
}
