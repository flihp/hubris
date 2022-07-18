// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg_attr(not(test), no_std)]

use core::{mem, ptr, str::FromStr};
use hkdf::Hkdf;
use hubpack::SerializedSize;
use salty::constants::SECRETKEY_SEED_LENGTH;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use unwrap_lite::UnwrapLite;
use zeroize::Zeroize;

mod cert;
pub use crate::cert::{AliasCert, CertError, DeviceIdCert};
mod alias_cert_tmpl;
mod handoff;
mod id_cert_tmpl;
pub use crate::handoff::{AliasHandoff, Handoff};

pub const SEED_LENGTH: usize = SECRETKEY_SEED_LENGTH;
pub const SN_LENGTH: usize = id_cert_tmpl::SN_LENGTH;

pub trait SeedBuf {
    fn as_bytes(&self) -> &[u8; SEED_LENGTH];
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Cdi([u8; SEED_LENGTH]);

impl SeedBuf for Cdi {
    fn as_bytes(&self) -> &[u8; SEED_LENGTH] {
        &self.0
    }
}

impl Cdi {
    const REG_ADDR_NONSEC: u32 = 0x40000900;
    const REG_ADDR_SEC: u32 = 0x50000900;

    // Read the CDI from registers & return to the caller.
    // Clear the CDI after it's consumed to prevent future access.
    pub fn new() -> Option<Self> {
        let mut cdi = [0u8; SEED_LENGTH];
        let mut offset: usize = 0;
        let mut addr = Self::REG_ADDR_NONSEC;

        let step = mem::size_of::<u32>();
        // read out CDI
        while offset < cdi.len() {
            let p = addr as *const u32;
            // core::ptr::read is unsafe by definition.
            // Support from the lpc55-pac would help:
            // https://github.com/lpc55/lpc55-pac/issues/15
            // https://github.com/lpc55/lpc55-pac/pull/16
            let n = unsafe { ptr::read_volatile(p) };

            cdi[offset..offset + step].copy_from_slice(&n.to_ne_bytes());

            offset += step;
            addr += step as u32;
        }

        // lpc55 manual has contradictory text in UM11126 v2.4 as to whether
        // reading the CDI registers will cause CDI value to be cleared by
        // the NXP ROM. Experimentation shows that the CDI value is *not*
        // cleared after it's read and so we must do this ourselves.
        Cdi::clear_registers();

        // lpc55 CDI registers return 0 when DICE is disabled
        if !cdi.iter().all(|&w| w == 0) {
            Some(Self(cdi))
        } else {
            None
        }
    }

    // According to NXP LPC55 UM 11126 §4.5.74:
    // "Once CDI is computed and consumed, contents of those registers will
    // be erased by ROM."
    // In testing however the CDI is not cleared after it's consumed. This
    // function overwites the CDI with 0's doing the ROMs job for it.
    fn clear_registers() {
        let addr = Self::REG_ADDR_NONSEC;

        let mut offset: u32 = 0;
        let step: u32 = mem::size_of::<u32>().try_into().unwrap_lite();
        while (offset as usize) < SEED_LENGTH {
            let p = (addr + offset) as *mut u32;

            unsafe {
                ptr::write(p, 0);
            }

            offset += step;
        }
    }

    fn _is_reg_clear(addr: u32) -> bool {
        let mut offset: u32 = 0;
        let step: u32 = mem::size_of::<u32>().try_into().unwrap_lite();
        // read out CDI
        while (offset as usize) < SEED_LENGTH {
            let n = unsafe { ptr::read((addr + offset) as *const u32) };

            if n != 0 {
                return false;
            }

            offset += step;
        }

        true
    }

    // Read the CDI directly from the registers. If any of the registers are
    // non-zero, then this function returns false.
    pub fn is_reg_clear() -> bool {
        Self::_is_reg_clear(Self::REG_ADDR_NONSEC)
            || Self::_is_reg_clear(Self::REG_ADDR_SEC)
    }

    pub fn clear(&self) {
        let mut offset: usize = 0;
        let mut addr = Self::REG_ADDR_NONSEC;

        let step = mem::size_of::<u32>();
        while offset < self.0.len() {
            let p = addr as *mut u32;

            unsafe {
                ptr::write(p, 0);
            }

            offset += step;
            addr += step as u32;
        }
    }
}

/// This function creates output keying material (OKM) using the Hkdf-extract-
/// and-expand to expand the seed using the provided info. The extract step is
/// skipped and so the seed MUST be sufficiently strong cryptographically for
/// use as a key itself (see RFC 5869 §3.3).
fn okm_from_seed_no_extract<S: SeedBuf>(
    seed: &S,
    info: &[u8],
) -> [u8; SEED_LENGTH] {
    let mut okm = [0u8; SEED_LENGTH];
    let hk =
        Hkdf::<Sha3_256>::from_prk(seed.as_bytes()).expect("Hkdf::from_prk");
    // TODO: return error instead of expect
    hk.expand(info, &mut okm).expect("failed to expand");

    okm
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DeviceIdOkm([u8; SEED_LENGTH]);

impl DeviceIdOkm {
    // Use HKDF to to generate output keying material from CDI.
    // This assumes that the CDI is sufficiently random that no seed is
    // required (lpc55 uses PUF to create UDS).
    pub fn from_cdi(cdi: &Cdi) -> Self {
        Self(okm_from_seed_no_extract(cdi, "identity".as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8; SEED_LENGTH] {
        &self.0
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Serialize, SerializedSize,
)]
pub struct SerialNumber([u8; SN_LENGTH]);

#[derive(Clone, Copy, Debug)]
pub enum SNError {
    BadSize,
}

impl FromStr for SerialNumber {
    type Err = SNError;

    fn from_str(sn: &str) -> Result<Self, Self::Err> {
        // TODO: error handling
        //Self(sn.as_bytes().try_into())
        let sn: [u8; SN_LENGTH] =
            sn.as_bytes().try_into().map_err(|_| SNError::BadSize)?;
        Ok(Self(sn))
    }
}

impl SerialNumber {
    pub fn from_bytes(sn: &[u8; SN_LENGTH]) -> Self {
        Self(*sn)
    }

    pub fn as_bytes(&self) -> &[u8; SN_LENGTH] {
        &self.0
    }
}

/// CdiL1 is a type that represents the compound device identifier (CDI) that's
/// derived from the Cdi and a seed value. This seed value must be the TCB
/// component identifier (TCI) representing the layer 1 (L1) firmware. This is
/// the hash of the Hubris image booted.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct CdiL1([u8; SEED_LENGTH]);

impl SeedBuf for CdiL1 {
    fn as_bytes(&self) -> &[u8; SEED_LENGTH] {
        &self.0
    }
}

impl CdiL1 {
    pub fn new(cdi: &Cdi, salt: &[u8; SEED_LENGTH]) -> Self {
        let mut okm = [0u8; SEED_LENGTH];
        // TODO: Not sure FWID should be the salt here as we don't know much
        // about its entropy content (hash of FW). The CDI should have good
        // entropy though so maybe the CDI should be the salt and the FWID
        // should be the IKM? Does it matter?
        let hk = Hkdf::<Sha3_256>::new(Some(salt), cdi.as_bytes());
        // No info provided to 'expand', see RFC 5869 §3.2.
        // TODO: return error instead of expect
        hk.expand(&[], &mut okm).expect("failed to expand");

        CdiL1(okm)
    }
}

/// AliasOkm is a type that represents the output keying material (OKM) used
/// to create the Alias key. This key is used to attest to the measurements
/// collected by the platform.
#[derive(Deserialize, Serialize, SerializedSize, Zeroize)]
#[zeroize(drop)]
pub struct AliasOkm([u8; SEED_LENGTH]);

impl SeedBuf for AliasOkm {
    fn as_bytes(&self) -> &[u8; SEED_LENGTH] {
        &self.0
    }
}

impl AliasOkm {
    pub fn from_cdi(cdi: &CdiL1) -> Self {
        Self(okm_from_seed_no_extract(cdi, "attestation".as_bytes()))
    }
}
