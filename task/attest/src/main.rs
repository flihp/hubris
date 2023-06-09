// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Root of trust for reporting (RoT-R) task.
//!
//! Use the attest-api crate to interact with this task.

#![no_std]
#![no_main]

use attest_api::AttestError;
use core::mem::MaybeUninit;
use dice::{AliasData, CertData};
use idol_runtime::{ClientError, Leased, RequestError, W};
use ringbuf::{ringbuf, ringbuf_entry};
use stage0_handoff::{HandoffData, HandoffDataLoadError};
use zerocopy::AsBytes;

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    Cert,
    CertChainLen(u32),
    CertLen(usize),
    AttestError(AttestError),
    HandoffError(HandoffDataLoadError),
    BufSize(usize),
    Index(u32),
    Offset(u32),
    Startup,
    None,
}

ringbuf!(Trace, 16, Trace::None);

// NOTE: Our use of 'link_section' below relies on the behavior of `xtask`.
// The sizes assigned to each of these sections in the app.toml is the
// same as the sizes of the MaybeUninit inner types below. This causes
// both of the MaybeUninits to be mapped to the base of memory in their
// respective sections.
// TODO: consider replacing with the `extern-region` mechanism

// Map the memory used to pass the segment of the identity cert chain common
// to all tasks to a variable.
#[used]
#[link_section = ".dice_certs"]
static CERTS: MaybeUninit<[u8; 0xa00]> = MaybeUninit::uninit();

// Map the memory used to pass artifacts intended for the attestation
// responder.
#[used]
#[link_section = ".dice_alias"]
static ALIAS: MaybeUninit<[u8; 0x800]> = MaybeUninit::uninit();

struct AttestServer {
    alias_data: Option<AliasData>,
    cert_data: Option<CertData>,
}

impl Default for AttestServer {
    fn default() -> Self {
        // Safety: This memory is setup by code executed before hubris.
        let addr = unsafe { ALIAS.assume_init_ref() };
        let alias_data = match AliasData::load_from_addr(addr) {
            Ok(d) => Some(d),
            Err(e) => {
                ringbuf_entry!(Trace::HandoffError(e));
                None
            }
        };

        // Safety: This memory is setup by code executed before hubris.
        let addr = unsafe { CERTS.assume_init_ref() };
        let cert_data = match CertData::load_from_addr(addr) {
            Ok(d) => Some(d),
            Err(e) => {
                ringbuf_entry!(Trace::HandoffError(e));
                None
            }
        };

        Self {
            alias_data,
            cert_data,
        }
    }
}

impl AttestServer {
    fn get_alias_data(&self) -> Result<&AliasData, AttestError> {
       match &self.alias_data {
           Some(d) => Ok(d),
           None => Err(AttestError::NoCerts.into())
        }
    }

    fn get_cert_data(&self) -> Result<&CertData, AttestError> {
       match &self.cert_data {
           Some(d) => Ok(d),
           None => Err(AttestError::NoCerts.into())
        }
    }

    fn get_cert_bytes_from_index(
        &self,
        index: u32,
    ) -> Result<&[u8], RequestError<AttestError>> {
        let alias_data = self.get_alias_data()?;
        let cert_data = self.get_cert_data()?;

        match index {
            // Cert chains start with the leaf and stop at the last
            // intermediate before the root. We mimic an array with
            // the leaf cert at index 0, and the last intermediate as
            // the chain length - 1.
            0 => Ok(alias_data.alias_cert.as_bytes()),
            1 => Ok(cert_data.deviceid_cert.as_bytes()),
            2 => Ok(&cert_data.persistid_cert.0.as_bytes()
                [0..cert_data.persistid_cert.0.size as usize]),
            3 => {
                if let Some(cert) = cert_data.intermediate_cert.as_ref() {
                    Ok(&cert.0.as_bytes()[0..cert.0.size as usize])
                } else {
                    Err(AttestError::InvalidCertIndex.into())
                }
            }
            _ => Err(AttestError::InvalidCertIndex.into()),
        }
    }
}

impl idl::InOrderAttestImpl for AttestServer {
    /// Get length of cert chain from Alias to mfg intermediate
    fn cert_chain_len(
        &mut self,
        _: &userlib::RecvMessage,
    ) -> Result<u32, RequestError<AttestError>> {
        let cert_data = self.get_cert_data()?;
        // The cert chain will vary in length:
        // - kernel w/ feature 'dice-self' will have 3 certs in the chain w/
        // the final cert being a self signed, puf derived identity key
        // - kernel /w feature 'dice-mfg' will have 4 certs in the chain w/
        // the final cert being the intermediate that signs the identity
        // cert
        let chain_len = if cert_data.intermediate_cert.is_none() {
            3
        } else {
            4
        };

        ringbuf_entry!(Trace::CertChainLen(chain_len));
        Ok(chain_len)
    }

    /// Get length of cert at provided index in cert chain
    fn cert_len(
        &mut self,
        _: &userlib::RecvMessage,
        index: u32,
    ) -> Result<u32, RequestError<AttestError>> {
        let len = self.get_cert_bytes_from_index(index)?.len();
        ringbuf_entry!(Trace::CertLen(len));

        let len = u32::try_from(len).map_err(|_| {
            <AttestError as Into<RequestError<AttestError>>>::into(
                AttestError::CertTooBig,
            )
        })?;

        Ok(len)
    }

    /// Get a cert from the AliasCert chain
    fn cert(
        &mut self,
        _: &userlib::RecvMessage,
        index: u32,
        offset: u32,
        dest: Leased<W, [u8]>,
    ) -> Result<(), RequestError<AttestError>> {
        ringbuf_entry!(Trace::Cert);
        ringbuf_entry!(Trace::Index(index));
        ringbuf_entry!(Trace::Offset(offset));
        ringbuf_entry!(Trace::BufSize(dest.len()));

        let cert = self.get_cert_bytes_from_index(index)?;
        if cert.is_empty() {
            let err = AttestError::InvalidCertIndex;
            ringbuf_entry!(Trace::AttestError(err));
            return Err(err.into());
        }

        // there must be sufficient data read from cert to fill the lease
        if dest.len() > cert.len() - offset as usize {
            let err = AttestError::OutOfRange;
            ringbuf_entry!(Trace::AttestError(err));
            return Err(err.into());
        }

        let offset = offset as usize;
        dest.write_range(0..dest.len(), &cert[offset..offset + dest.len()])
            .map_err(|_| RequestError::Fail(ClientError::WentAway))?;

        Ok(())
    }
}

#[export_name = "main"]
fn main() -> ! {
    ringbuf_entry!(Trace::Startup);

    let mut buffer = [0; idl::INCOMING_SIZE];
    let mut attest = AttestServer::default();
    loop {
        idol_runtime::dispatch(&mut buffer, &mut attest);
    }
}

mod idl {
    use super::AttestError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
