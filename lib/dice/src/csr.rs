// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::csr_tmpl;
pub use hubpack::{deserialize, serialize, SerializedSize};
use salty::constants::{
    PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH,
};
use salty::signature::{Keypair, PublicKey, Signature};
pub use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

// #[cfg(feature = "std")]
// use std::{error::Error, fmt};

#[derive(Debug, PartialEq)]
pub enum CsrError {
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
pub struct Csr(#[serde(with = "BigArray")] [u8; csr_tmpl::SIZE]);

impl Csr {
    pub fn new(cn: &[u8; csr_tmpl::CN_LENGTH]) -> Self {
        let mut buf = [0u8; csr_tmpl::SIZE];

        csr_tmpl::fill(&mut buf, cn);

        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8; csr_tmpl::SIZE] {
        &self.0
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get_pub(&self) -> &[u8; PUBLICKEY_SERIALIZED_LENGTH] {
        self.as_bytes()[csr_tmpl::PUB_START..csr_tmpl::PUB_END]
            .try_into()
            .unwrap()
    }

    pub fn set_pub(&mut self, pubkey: &[u8; PUBLICKEY_SERIALIZED_LENGTH]) {
        self.0[csr_tmpl::PUB_START..csr_tmpl::PUB_END].copy_from_slice(pubkey);
    }

    pub fn get_sig(&self) -> &[u8; SIGNATURE_SERIALIZED_LENGTH] {
        self.as_bytes()[csr_tmpl::SIG_START..csr_tmpl::SIG_END]
            .try_into()
            .unwrap()
    }

    pub fn set_sig(&mut self, sig: &[u8; SIGNATURE_SERIALIZED_LENGTH]) {
        self.0[csr_tmpl::SIG_START..csr_tmpl::SIG_END].copy_from_slice(sig);
    }

    pub fn get_signdata(&self) -> &[u8; csr_tmpl::SIGNDATA_LENGTH] {
        self.as_bytes()[csr_tmpl::SIGNDATA_START..csr_tmpl::SIGNDATA_END]
            .try_into()
            .unwrap()
    }

    /// This function uses the provided key pair to generate a signature for
    /// the CSR. The public key and the signature are then written to the
    /// appropriate locations in the CSR.
    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), CsrError> {
        // the public key must be part of the data signed:
        // set it before signing
        let public_bytes = keypair.public.as_bytes();
        self.set_pub(public_bytes);

        // sign CSR data
        let sign_data = self.get_signdata();
        let sig = keypair.sign(sign_data);

        // verify the signature before we write it to the csr
        // TODO: return error, not expect
        keypair.public.verify(sign_data, &sig).expect("verify");

        // set new signature
        self.set_sig(&sig.to_bytes());

        Ok(())
    }

    pub fn check_sig(&self) -> Result<(), CsrError> {
        let pubkey = match PublicKey::try_from(self.get_pub()) {
            Ok(pubkey) => pubkey,
            Err(_) => panic!("check_sig"),
        };
        let sig = match Signature::try_from(self.get_sig()) {
            Ok(sig) => sig,
            Err(_) => panic!("check_sig"),
        };
        let sign_data = self.get_signdata();

        pubkey.verify(sign_data, &sig).expect("verify");

        Ok(())
    }
}
