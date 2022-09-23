// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::cert::{Cert, DeviceIdSelfCertBuilder};
use crate::csr::DeviceIdCsrBuilder;
use crate::{CertSerialNumber, SerialNumber};
use core::str::FromStr;
use dice_mfg_msgs::{Msg, Msgs, SizedBlob};
use hubpack::SerializedSize;
use lib_lpc55_usart::{Read, Usart, Write};
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, SerializedSize)]
pub struct CertChain {
    pub device_id: SizedBlob,
    pub intermediate: SizedBlob,
}

// data returned to caller by MFG
// typically required to use ECA post MFG
// this is what gets written to persistent storage after successful mfg
pub struct DiceState {
    pub cert_serial_number: CertSerialNumber,
    pub serial_number: SerialNumber,
    pub cert_chain: CertChain,
}

pub enum Error {
    MsgDecode,
    MsgBufFull,
    UsartRead,
    UsartWrite,
}

pub struct DeviceIdSelfMfg;

impl DeviceIdSelfMfg {
    pub fn run(keypair: &Keypair) -> DiceState {
        let mut cert_sn: CertSerialNumber = Default::default();
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
                // TODO: static assert deviceid_cert size < SizedBuf max
                device_id: SizedBlob::try_from(deviceid_cert.as_bytes())
                    .expect("deviceid cert to SizedBlob"),
                intermediate: SizedBlob::default(),
            },
        }
    }
}

pub struct DeviceIdSerialMfg<'a> {
    keypair: &'a Keypair,
    usart: &'a mut Usart<'a>,
    buf: [u8; Msg::MAX_ENCODED_SIZE],
    serial_number: Option<SerialNumber>,
    deviceid_cert: Option<SizedBlob>,
    intermediate_cert: Option<SizedBlob>,
}

impl<'a> DeviceIdSerialMfg<'a> {
    // use associated type for the message type?

    pub fn new(keypair: &'a Keypair, usart: &'a mut Usart<'a>) -> Self {
        DeviceIdSerialMfg {
            keypair,
            usart,
            buf: [0u8; Msg::MAX_ENCODED_SIZE],
            serial_number: None,
            deviceid_cert: None,
            intermediate_cert: None,
        }
    }

    pub fn run(mut self) -> DiceState {
        loop {
            let msg = match self.get_msg() {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            let _ = match msg.msg {
                Msgs::Break => {
                    if self.serial_number.is_none()
                        || self.deviceid_cert.is_none()
                        || self.intermediate_cert.is_none()
                    {
                        let _ = self.send_nak();
                        continue;
                    } else {
                        let _ = self.send_ack();
                        break;
                    }
                }
                Msgs::BreakForce => {
                    let _ = self.send_ack();
                    break;
                },
                Msgs::CsrPlz => self.handle_csrplz(),
                Msgs::DeviceIdCert(cert) => self.handle_deviceid_cert(cert),
                Msgs::IntermediateCert(cert) => {
                    self.handle_intermediate_cert(cert)
                }
                Msgs::Ping => self.send_ack(),
                Msgs::SerialNumber(sn) => {
                    self.handle_serial_number(SerialNumber::from_bytes(&sn))
                }
                _ => continue,
            };
        }

        let _ = flush_all(self.usart);

        DiceState {
            cert_serial_number: CertSerialNumber::default(),
            serial_number: self.serial_number.unwrap(),
            cert_chain: CertChain {
                device_id: self.deviceid_cert.unwrap(),
                intermediate: self.intermediate_cert.unwrap(),
            },
        }
    }

    fn handle_serial_number(
        &mut self,
        serial_number: SerialNumber
    ) -> Result<(), Error> {
        self.serial_number = Some(serial_number);

        self.send_ack()
    }

    fn handle_csrplz(&mut self) -> Result<(), Error> {
        if self.serial_number.is_none() {
            return self.send_nak();
        }

        let csr = DeviceIdCsrBuilder::new(
            &self.serial_number.unwrap(),
            &self.keypair.public,
        )
        .sign(&self.keypair);

        self.send_csr(csr)
    }

    fn send_csr(&mut self, csr: SizedBlob) -> Result<(), Error> {
        self.send_msg(Msg {
            id: 0,
            msg: Msgs::Csr(csr.clone()),
        })
    }

    fn handle_deviceid_cert(&mut self, cert: SizedBlob) -> Result<(), Error> {
        self.deviceid_cert = Some(cert);

        self.send_ack()
    }

    fn handle_intermediate_cert(&mut self, cert: SizedBlob) -> Result<(), Error> {
        self.intermediate_cert = Some(cert);

        self.send_ack()
    }

    fn send_ack(&mut self) -> Result<(), Error> {
        let msg = Msg {
            id: 0,
            msg: Msgs::Ack,
        };

        self.send_msg(msg)
    }

    fn send_nak(&mut self) -> Result<(), Error> {
        let msg = Msg {
            id: 0,
            msg: Msgs::Nak,
        };

        self.send_msg(msg)
    }

    fn get_msg(&mut self) -> Result<Msg, Error> {
        let buf = &mut self.buf;

        match read_until(self.usart, buf, &[0]) {
            Ok(size) => Msg::decode(&buf[..size]).map_err(|_| Error::MsgDecode),
            Err(_) => Err(Error::UsartRead),
        }
    }

    fn send_msg(&mut self, msg: Msg) -> Result<(), Error> {
        self.buf.fill(0);

        let size = msg.encode(&mut self.buf).expect("encode msg");
        write_all(self.usart, &self.buf[..size])
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
                Err(nb::Error::Other(_)) => return Err(Error::UsartWrite),
            }
        }
    }
    Ok(())
}

fn flush_all(usart: &mut Usart) -> Result<(), Error> {
    let mut done = false;

    while !done {
        done = match usart.flush() {
            Ok(_) => true,
            Err(nb::Error::WouldBlock) => false,
            Err(nb::Error::Other(_)) => return Err(Error::UsartWrite),
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
                    return Err(Error::MsgBufFull);
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
            Err(nb::Error::Other(_)) => return Err(Error::UsartWrite),
        }
    }
    Ok(pos)
}
