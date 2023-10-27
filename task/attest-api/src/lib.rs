// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! API crate for the 'attest' task.

#![no_std]

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::Sha512VarCore;
use sha3::{
    digest::{typenum::Unsigned, OutputSizeUser},
    Sha3_256Core
};
use userlib::sys_send;

#[derive(
    Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum AttestError {
    CertTooBig,
    InvalidCertIndex,
    NoCerts,
    OutOfRange,
    LogFull,
    LogTooBig,
    TaskRestarted,
    BadLease,
    UnsupportedAlgorithm,
    SerializeLog,
    SerializeSignature,
    SignatureTooBig,
}

impl From<idol_runtime::ServerDeath> for AttestError {
    fn from(_: idol_runtime::ServerDeath) -> Self {
        AttestError::TaskRestarted
    }
}

#[derive(
    Copy, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SerializedSize,
)]
pub enum HashAlgorithm {
    Sha3_256,
}

include!(concat!(env!("OUT_DIR"), "/client_stub.rs"));

// structures to support attestation
#[derive(Clone, Copy, PartialEq, Deserialize, Serialize, SerializedSize)]
pub enum Signature {
    Ed25519(Sha512Digest),
}

impl Default for Signature {
    fn default() -> Self {
        Signature::Ed25519(Sha512Digest::default())
    }
}

// Digest is a fixed length array of bytes
#[serde_as]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize, SerializedSize)]
pub struct Digest<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Default for Digest<N> {
    fn default() -> Self {
        Digest([0u8; N])
    }
}

// the size of an ed25519 signature
pub const SHA_512_DIGEST_SIZE: usize =
    <Sha512VarCore as OutputSizeUser>::OutputSize::USIZE;

// the size of the measurements we record
pub const SHA3_256_DIGEST_SIZE: usize =
    <Sha3_256Core as OutputSizeUser>::OutputSize::USIZE;

pub type Sha512Digest = Digest<SHA_512_DIGEST_SIZE>;
pub type Sha3_256Digest = Digest<SHA3_256_DIGEST_SIZE>;
