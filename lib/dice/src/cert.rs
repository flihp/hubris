// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{cert_tmpl, leafcert_tmpl, SerialNumber};
use hubpack::SerializedSize;
use salty::constants::{
    PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH,
};
use salty::signature::Keypair;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use unwrap_lite::UnwrapLite;

#[derive(Debug, PartialEq)]
pub enum CertError {
    BadSig,
    NoPubKey,
    NoSig,
    NoSignData,
    TooSmall,
    NotFound,
    NoCn,
}

#[derive(
    Clone, Copy, Debug, PartialEq, Deserialize, Serialize, SerializedSize,
)]
pub struct DeviceIdCert(#[serde(with = "BigArray")] [u8; cert_tmpl::SIZE]);

impl DeviceIdCert {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut buf = [0u8; cert_tmpl::SIZE];
        cert_tmpl::fill(&mut buf);

        Self(buf)
    }

    pub fn from(bytes: &[u8; cert_tmpl::SIZE]) -> Self {
        Self(*bytes)
    }

    pub fn as_bytes(&self) -> &[u8; cert_tmpl::SIZE] {
        &self.0
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn set_serial_number(&mut self, sn: u8) -> Self {
        self.0[cert_tmpl::SERIAL_NUMBER_START..cert_tmpl::SERIAL_NUMBER_END]
            .copy_from_slice(&sn.to_be_bytes());

        *self
    }

    pub fn set_issuer_sn(&mut self, sn: &SerialNumber) -> Self {
        self.0[cert_tmpl::ISSUER_SN_START..cert_tmpl::ISSUER_SN_END]
            .copy_from_slice(sn.as_bytes());

        *self
    }

    pub fn set_notbefore(
        &mut self,
        utctime: &[u8; cert_tmpl::NOTBEFORE_LENGTH],
    ) -> Self {
        self.0[cert_tmpl::NOTBEFORE_START..cert_tmpl::NOTBEFORE_END]
            .copy_from_slice(utctime);

        *self
    }

    pub fn set_subject_sn(&mut self, sn: &SerialNumber) -> Self {
        self.0[cert_tmpl::SUBJECT_SN_START..cert_tmpl::SUBJECT_SN_END]
            .copy_from_slice(sn.as_bytes());

        *self
    }

    pub fn set_pub(
        &mut self,
        pubkey: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    ) -> Self {
        self.0[cert_tmpl::PUB_START..cert_tmpl::PUB_END]
            .copy_from_slice(pubkey);

        *self
    }

    pub fn set_sig(&mut self, sig: &[u8; SIGNATURE_SERIALIZED_LENGTH]) -> Self {
        self.0[cert_tmpl::SIG_START..cert_tmpl::SIG_END].copy_from_slice(sig);

        *self
    }

    fn get_signdata(&self) -> &[u8; cert_tmpl::SIGNDATA_LENGTH] {
        self.0[cert_tmpl::SIGNDATA_START..cert_tmpl::SIGNDATA_END]
            .try_into()
            .unwrap_lite()
    }

    pub fn sign(&mut self, keypair: &Keypair) -> Self {
        // calculate signature
        let signdata = self.get_signdata();
        let sig = keypair.sign(signdata);

        // set signature
        self.set_sig(&sig.to_bytes())
    }
}

#[derive(
    Clone, Copy, Debug, PartialEq, Deserialize, Serialize, SerializedSize,
)]
pub struct AliasCert(#[serde(with = "BigArray")] [u8; leafcert_tmpl::SIZE]);

impl AliasCert {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut buf = [0u8; leafcert_tmpl::SIZE];
        leafcert_tmpl::fill(&mut buf);

        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8; leafcert_tmpl::SIZE] {
        &self.0
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn set_serial_number(&mut self, sn: u8) -> Self {
        self.0[leafcert_tmpl::SERIAL_NUMBER_START
            ..leafcert_tmpl::SERIAL_NUMBER_END]
            .copy_from_slice(&sn.to_be_bytes());

        *self
    }

    pub fn set_issuer_sn(&mut self, sn: &SerialNumber) -> Self {
        self.0[leafcert_tmpl::ISSUER_SN_START..leafcert_tmpl::ISSUER_SN_END]
            .copy_from_slice(sn.as_bytes());

        *self
    }

    pub fn set_subject_sn(&mut self, sn: &SerialNumber) -> Self {
        self.0[leafcert_tmpl::SUBJECT_SN_START..leafcert_tmpl::SUBJECT_SN_END]
            .copy_from_slice(sn.as_bytes());

        *self
    }

    pub fn set_pub(
        &mut self,
        pubkey: &[u8; PUBLICKEY_SERIALIZED_LENGTH],
    ) -> Self {
        self.0[leafcert_tmpl::PUB_START..leafcert_tmpl::PUB_END]
            .copy_from_slice(pubkey);

        *self
    }

    fn set_sig(&mut self, sig: &[u8; SIGNATURE_SERIALIZED_LENGTH]) -> Self {
        self.0[leafcert_tmpl::SIG_START..leafcert_tmpl::SIG_END]
            .copy_from_slice(sig);

        *self
    }

    pub fn set_fwid(
        &mut self,
        fwid: &[u8; leafcert_tmpl::FWID_LENGTH],
    ) -> Self {
        self.0[leafcert_tmpl::FWID_START..leafcert_tmpl::FWID_END]
            .copy_from_slice(fwid);

        *self
    }

    fn get_signdata(&self) -> &[u8; leafcert_tmpl::SIGNDATA_LENGTH] {
        self.0[leafcert_tmpl::SIGNDATA_START..leafcert_tmpl::SIGNDATA_END]
            .try_into()
            .unwrap_lite()
    }

    // don't return Self, once it's signed you don't want to change it
    pub fn sign(&mut self, keypair: &Keypair) -> Self {
        // calculate signature
        let signdata = self.get_signdata();
        let sig = keypair.sign(signdata);

        // set signature
        self.set_sig(&sig.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::str::FromStr;

    fn get_issuer_sn(cert: &DeviceIdCert) -> &[u8; 12] {
        cert.0[cert_tmpl::ISSUER_SN_START..cert_tmpl::ISSUER_SN_END]
            .try_into()
            .unwrap_lite()
    }

    fn get_subject_sn(cert: &DeviceIdCert) -> &[u8; 12] {
        cert.0[cert_tmpl::SUBJECT_SN_START..cert_tmpl::SUBJECT_SN_END]
            .try_into()
            .unwrap_lite()
    }

    fn get_serial_number(cert: &DeviceIdCert) -> u8 {
        u8::from_be_bytes(
            cert.0
                [cert_tmpl::SERIAL_NUMBER_START..cert_tmpl::SERIAL_NUMBER_END]
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn serial_number_from_new() {
        let sn: u8 = 0x10;
        let cert = DeviceIdCert::new().set_serial_number(sn);

        assert_eq!(sn, get_serial_number(&cert));
    }

    #[test]
    fn issuer_sn_from_new() {
        let sn = SerialNumber::from_str("0123456789ab").expect("SN from_str");
        let cert = DeviceIdCert::new().set_issuer_sn(&sn);

        assert_eq!(get_issuer_sn(&cert), sn.as_bytes());
    }

    #[test]
    fn subject_cn_from_new() {
        let sn = SerialNumber::from_str("0123456789ab").expect("SN from_str");
        let cert = DeviceIdCert::new().set_subject_sn(&sn);

        assert_eq!(get_subject_sn(&cert), sn.as_bytes());
    }

    // Signature over CERT with issuer / subject SN & PUBKEY set according
    // to 'sign' test below.
    const SIG_EXPECTED: [u8; SIGNATURE_SERIALIZED_LENGTH] = [
        0x70, 0x5E, 0xFC, 0xFF, 0x89, 0x5E, 0xE9, 0x8C, 0xBC, 0x2C, 0x3C, 0x08,
        0x6D, 0x73, 0x87, 0xAB, 0xC4, 0xCA, 0x4F, 0xEA, 0xD8, 0x41, 0x42, 0xC7,
        0x62, 0x13, 0x2E, 0x65, 0x3F, 0xC0, 0x7B, 0xA5, 0x39, 0x31, 0x6D, 0x8D,
        0xD8, 0xBC, 0x71, 0x92, 0xE1, 0x42, 0x79, 0xF0, 0x23, 0xC0, 0x56, 0x75,
        0xA2, 0xB7, 0xED, 0xD6, 0xA9, 0xD0, 0xFB, 0xC2, 0x98, 0x4A, 0x50, 0x35,
        0x37, 0x76, 0xDA, 0x0E,
    ];

    // Each time this library is built the notBefore time in the validity
    // sequence will change so to get a consistent signature we set it to a
    // fixed point in time.
    #[test]
    fn sign() {
        extern crate alloc;
        use chrono::{
            prelude::{DateTime, Utc},
            TimeZone,
        };

        // well known seed
        let seed: [u8; 32] = [42; 32];
        let keypair: salty::Keypair = salty::Keypair::from(&seed);

        let sn = SerialNumber::from_str("0123456789ab").expect("SN from_str");
        let utc: DateTime<Utc> = Utc.ymd(2022, 07, 13).and_hms(6, 6, 6);
        let utc = utc.format("%y%m%d%H%M%SZ").to_string();
        let mut cert = DeviceIdCert::new()
            .set_issuer_sn(&sn)
            .set_notbefore(utc.as_bytes().try_into().expect("utc as_bytes"))
            .set_subject_sn(&sn)
            .set_pub(&keypair.public.as_bytes());

        cert.sign(&keypair);

        for (index, byte) in cert.as_bytes()
            [cert_tmpl::SIG_START..cert_tmpl::SIG_END]
            .iter()
            .enumerate()
        {
            if index % 12 == 11 {
                println!("{:#04X},", byte);
            } else {
                print!("{:#04X}, ", byte);
            }
        }
        assert_eq!(
            cert.0[cert_tmpl::SIG_START..cert_tmpl::SIG_END],
            SIG_EXPECTED
        );
    }
}
