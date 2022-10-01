// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{
    cert::{Cert, DeviceIdSelfCertBuilder},
    csr::DeviceIdCsrBuilder,
    CertSerialNumber, SerialNumber,
};
use core::str::FromStr;
use dice_mfg_msgs::{Msg, Msgs, SizedBlob};
use lib_lpc55_usart::{Read, Usart, Write};
use nb;
use salty::signature::Keypair;

pub enum Error {
    MsgDecode,
    MsgBufFull,
    UsartRead,
    UsartWrite,
}

// data returned to caller by MFG
// typically required to use ECA post MFG
// this is what gets written to persistent storage after successful mfg
pub struct DiceMfgState {
    pub cert_serial_number: CertSerialNumber,
    pub serial_number: SerialNumber,
    pub deviceid_cert: SizedBlob,
    pub intermediate_cert: SizedBlob,
}

pub trait DiceMfg {
    fn run(self) -> DiceMfgState;
}

pub struct DeviceIdSelfMfg<'a> {
    keypair: &'a Keypair,
}

impl<'a> DeviceIdSelfMfg<'a> {
    pub fn new(keypair: &'a Keypair) -> Self {
        Self { keypair }
    }
}

impl DiceMfg for DeviceIdSelfMfg<'_> {
    fn run(self) -> DiceMfgState {
        let mut cert_sn: CertSerialNumber = Default::default();
        let dname_sn =
            SerialNumber::from_str("0123456789ab").expect("DeviceIdSelf SN");

        let deviceid_cert = DeviceIdSelfCertBuilder::new(
            &cert_sn.next(),
            &dname_sn,
            &self.keypair.public,
        )
        .sign(self.keypair);

        DiceMfgState {
            cert_serial_number: cert_sn,
            serial_number: dname_sn,
            // TODO: static assert deviceid_cert size < SizedBuf max
            deviceid_cert: SizedBlob::try_from(deviceid_cert.as_bytes())
                .expect("deviceid cert to SizedBlob"),
            intermediate_cert: SizedBlob::default(),
        }
    }
}

pub struct DeviceIdSerialMfg<'a> {
    keypair: &'a Keypair,
    usart: Usart<'a>,
    buf: [u8; Msg::MAX_ENCODED_SIZE],
    serial_number: Option<SerialNumber>,
    deviceid_cert: Option<SizedBlob>,
    intermediate_cert: Option<SizedBlob>,
}

impl<'a> DeviceIdSerialMfg<'a> {
    pub fn new(keypair: &'a Keypair, usart: Usart<'a>) -> Self {
        Self {
            keypair,
            usart,
            buf: [0u8; Msg::MAX_ENCODED_SIZE],
            serial_number: None,
            deviceid_cert: None,
            intermediate_cert: None,
        }
    }

    /// The Break message is an indication from the mfg side of the comms
    /// that DeviceId manufacturing is complete. We check this as best we
    /// (currently) can by ensuring all of the necessary data has been
    /// received.
    fn handle_break(&mut self) -> bool {
        if self.serial_number.is_none()
            || self.deviceid_cert.is_none()
            || self.intermediate_cert.is_none()
        {
            let _ = self.send_nak();
            false
        } else {
            let _ = self.send_ack();
            true
        }
    }

    /// Handle a request for a CSR from the mfg system requires that we have
    /// already been given a serial number. If not we NAK the message.
    /// Otherwise we use the CSR builder to create a CSR that contains the
    /// serial number and DeviceId publie key. We then sign the CSR with the
    /// private part of the same key and send it back to the mfg system.
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

    fn handle_deviceid_cert(&mut self, cert: SizedBlob) -> Result<(), Error> {
        self.deviceid_cert = Some(cert);

        self.send_ack()
    }

    fn handle_intermediate_cert(
        &mut self,
        cert: SizedBlob,
    ) -> Result<(), Error> {
        self.intermediate_cert = Some(cert);

        self.send_ack()
    }

    /// Store the serial number provided by the mfg system. If we've already
    /// received a cert for the DeviceId we invalidate it. This is to prevent
    /// the mfg side from changing the SN after we've used it to create the
    /// DeviceId cert.
    fn handle_serial_number(
        &mut self,
        serial_number: SerialNumber,
    ) -> Result<(), Error> {
        if self.deviceid_cert.is_some() {
            self.deviceid_cert = None;
        }

        self.serial_number = Some(serial_number);

        self.send_ack()
    }

    fn send_ack(&mut self) -> Result<(), Error> {
        let msg = Msg {
            id: 0,
            msg: Msgs::Ack,
        };

        self.send_msg(msg)
    }

    fn send_csr(&mut self, csr: SizedBlob) -> Result<(), Error> {
        let msg = Msg {
            id: 0,
            msg: Msgs::Csr(csr),
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

        match read_until(&mut self.usart, buf, &[0]) {
            Ok(size) => Msg::decode(&buf[..size]).map_err(|_| Error::MsgDecode),
            Err(_) => Err(Error::UsartRead),
        }
    }

    fn send_msg(&mut self, msg: Msg) -> Result<(), Error> {
        self.buf.fill(0);

        let size = msg.encode(&mut self.buf).expect("encode msg");
        write_all(&mut self.usart, &self.buf[..size])
    }
}

impl DiceMfg for DeviceIdSerialMfg<'_> {
    fn run(mut self) -> DiceMfgState {
        loop {
            let msg = match self.get_msg() {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            let _ = match msg.msg {
                Msgs::Break => {
                    if self.handle_break() {
                        break;
                    } else {
                        continue;
                    }
                }
                Msgs::CsrPlz => self.handle_csrplz(),
                Msgs::DeviceIdCert(cert) => self.handle_deviceid_cert(cert),
                Msgs::IntermediateCert(cert) => {
                    self.handle_intermediate_cert(cert)
                }
                Msgs::Ping => self.send_ack(),
                Msgs::SerialNumber(sn) => {
                    let sn = SerialNumber::from_bytes(&sn);
                    self.handle_serial_number(sn)
                }
                _ => continue,
            };
        }

        flush_all(&mut self.usart);

        DiceMfgState {
            cert_serial_number: Default::default(),
            serial_number: self.serial_number.unwrap(),
            deviceid_cert: self.deviceid_cert.unwrap(),
            intermediate_cert: self.intermediate_cert.unwrap(),
        }
    }
}

/// Write all bytes in buf to usart fifo, poll if fifo is full.
/// NOTE: This does not guarantee transmission of all bytes. See flush_all.
fn write_all(usart: &mut Usart, src: &[u8]) -> Result<(), Error> {
    for b in src {
        let mut done = false;
        while !done {
            // use nb::block!
            done = match usart.write(*b) {
                Ok(_) => true,
                Err(nb::Error::WouldBlock) => false,
                Err(nb::Error::Other(_)) => return Err(Error::UsartWrite),
            }
        }
    }
    Ok(())
}

/// Poll the usart reading bytes into dst until a termination sequence is
/// found.
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
        // use nb::block!
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
                    // TODO: there's gotta be a better way:
                    // if dst[pos - term.len()] == term { ... }?
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
            Err(nb::Error::Other(_)) => return Err(Error::UsartRead),
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
            // flush only returns WouldBlock, ignore all others
            Err(_) => true,
        }
    }
}
