// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use attest_api::{Attest, AttestError};
use drv_rng_api::{Rng, RngError};
use rand_core::RngCore;
use ringbuf::{ringbuf, ringbuf_entry};
use userlib::{task_slot, TaskId};

task_slot!(ATTEST, attest);
task_slot!(RNG, rng_driver);

#[derive(Copy, Clone, PartialEq)]
enum Test {
    CertChainLen,
    CertChain,
    CertLen(u32),
    Chunk(u32),
    Remain(u32),
    Cert(u32),
    LogLen,
    Log,
    QuoteLen,
    Quote,
}

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    CertChainLen(u32),
    CertLen(u32),
    Chunk(u32),
    Remain(u32),
    Done,
    Error(AttestError),
    LogLen(u32),
    QuoteLen(u32),
    Nonce([u8; 32]),
    None,
    Start,
    StartTest(Test),
    QuoteTooBig,
    RngErr(RngError),
    CertTooBig,
}

ringbuf!(Trace, 32, Trace::None);

// prevent the task from being scheduled by waiting to recv a signal that
// will never come
fn done() -> u32 {
    ringbuf_entry!(Trace::Done);

    // wait for a signal from the kernel that will never come
    if userlib::sys_recv_closed(&mut [], 1, TaskId::KERNEL).is_err() {
        panic!();
    }

    // not reachable
    0
}

const CHUNK_SIZE: u32 = 256;
const NONCE_SIZE: usize = 32;

// wrapper to make getting stuff from the Attest task easier
struct AttestUtil {
    attest: Attest,
}

impl AttestUtil {
    const CHUNK_SIZE: u32 = CHUNK_SIZE;

    // get the number of certs in the attest / alias cert chain
    fn get_cert_chain_len(&self) -> u32 {
        self.attest.cert_chain_len().unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            done()
        })
    }

    // get the length of the certificate at `index` position in the chain
    fn get_cert_len(&self, index: u32) -> u32 {
        self.attest.cert_len(index).unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            done()
        })
    }

    fn get_cert_chunk(&mut self, index: u32, offset: u32, chunk: &mut [u8]) {
        self.attest.cert(index, offset, chunk).unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            done();
        });
    }

    // get the certificate with length `len` at `index` position in the cert chain
    // NOTE: though we get the whole certificate we only have a 256 byte chunk of
    // it at a time
    fn get_cert(&mut self, index: u32, dst: &mut [u8]) {
        let len = self.get_cert_len(index);
        if dst.len() < len as usize {
            ringbuf_entry!(Trace::CertTooBig);
            done();
        }

        let mut buf = [0u8; Self::CHUNK_SIZE as usize];

        // get certs in Self::CHUNK_SIZE byte chunks
        for chunk in 0..(len / Self::CHUNK_SIZE) {
            let offset = chunk * Self::CHUNK_SIZE;

            self.get_cert_chunk(index, offset, &mut buf);
            dst[offset as usize..(offset + Self::CHUNK_SIZE) as usize]
                .copy_from_slice(&buf);
        }

        let remain = len % Self::CHUNK_SIZE;
        if remain > 0 {
            let offset = len / Self::CHUNK_SIZE;
            self.get_cert_chunk(index, offset, &mut buf[..remain as usize]);
            dst[offset as usize..(offset + Self::CHUNK_SIZE) as usize]
                .copy_from_slice(&buf[..remain as usize]);
        }
    }

    // get length of attestation measurement log
    fn get_log_len(&self) -> u32 {
        self.attest.log_len().unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            done()
        })
    }

    fn get_log_chunk(&mut self, offset: u32, buf: &mut [u8]) {
        self.attest.log(offset, buf).unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            done();
        });
    }

    fn get_log(&mut self, dst: &mut [u8]) {
        let len = self.get_log_len();
        if dst.len() < len as usize {
            ringbuf_entry!(Trace::CertTooBig);
            done();
        }

        let mut buf = [0u8; Self::CHUNK_SIZE as usize];

        for chunk in 0..(len / Self::CHUNK_SIZE) {
            let offset = chunk * Self::CHUNK_SIZE;
            self.get_log_chunk(offset, &mut buf);
            dst[offset as usize..(offset + Self::CHUNK_SIZE) as usize]
                .copy_from_slice(&buf);
        }

        let remain = len % Self::CHUNK_SIZE;
        if remain > 0 {
            let offset = len / Self::CHUNK_SIZE;
            self.get_log_chunk(offset, &mut buf[..remain as usize]);
            dst[offset as usize..(offset + Self::CHUNK_SIZE) as usize]
                .copy_from_slice(&buf[..remain as usize]);
        }
    }

    fn get_quote_len(&self) -> u32 {
        self.attest.quote_len().unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            done()
        })
    }

    fn get_quote(&mut self, nonce: &[u8], dst: &mut [u8]) {
        let len = self.get_quote_len();
        // quote must be read in one operation -> must fit in a single self.chunk
        if len as usize > dst.len() {
            ringbuf_entry!(Trace::QuoteTooBig);
            done();
        }

        self.attest
            .quote(nonce, &mut dst[..len as usize])
            .unwrap_or_else(|e| {
                ringbuf_entry!(Trace::Error(e));
                done();
            });
        // check signature
        // - calculate log_hash = hash(log | nonce)
        // NOTE: manually verify log_hash matches hash created by attest task
        // matches using ringbuf
        // - get alias cert
        // - get pub key from alias cert
        // - create ed25519 verifier from pub key
        // - verify signature over log_hash calculated above
    }
}

impl Default for AttestUtil {
    fn default() -> Self {
        AttestUtil {
            attest: Attest::from(ATTEST.get_task_id()),
        }
    }
}

struct AttestTest {
    attest: AttestUtil,
}

impl AttestTest {
    const CHUNK_SIZE: u32 = CHUNK_SIZE;

    fn cert(&mut self, index: u32) {
        let len = self.attest.get_cert_len(index);

        ringbuf_entry!(Trace::StartTest(Test::Cert(index)));
        let mut buf = [0u8; Self::CHUNK_SIZE as usize];
        let mut offset = 0;
        // get certs in Self::CHUNK_SIZE byte chunks
        for chunk in 0..(len / Self::CHUNK_SIZE) {
            ringbuf_entry!(Trace::StartTest(Test::Chunk(chunk)));
            self.attest.get_cert_chunk(index, offset, &mut buf);
            ringbuf_entry!(Trace::Chunk(chunk));
            offset += Self::CHUNK_SIZE;
        }

        let remain = len % Self::CHUNK_SIZE;
        if remain > 0 {
            ringbuf_entry!(Trace::StartTest(Test::Remain(remain)));
            self.attest.get_cert_chunk(
                index,
                offset,
                &mut buf[..remain as usize],
            );
            ringbuf_entry!(Trace::Remain(remain));
        }
    }

    fn cert_chain(&mut self) {
        ringbuf_entry!(Trace::StartTest(Test::CertChainLen));
        let len = self.attest.get_cert_chain_len();
        ringbuf_entry!(Trace::CertChainLen(len));

        ringbuf_entry!(Trace::StartTest(Test::CertChain));
        for c in 0..len {
            ringbuf_entry!(Trace::StartTest(Test::CertLen(c)));
            let cert_len = self.attest.get_cert_len(c);
            ringbuf_entry!(Trace::CertLen(cert_len));
            self.cert(c);
        }
    }

    fn log(&mut self) {
        ringbuf_entry!(Trace::StartTest(Test::Log));
        let len = self.attest.get_log_len();
        ringbuf_entry!(Trace::LogLen(len));

        let mut buf = [0u8; Self::CHUNK_SIZE as usize];

        for chunk in 0..(len / Self::CHUNK_SIZE) {
            ringbuf_entry!(Trace::StartTest(Test::Chunk(chunk)));
            self.attest
                .get_log_chunk(chunk * Self::CHUNK_SIZE, &mut buf);
            ringbuf_entry!(Trace::Chunk(chunk));
        }

        let remain = len % Self::CHUNK_SIZE;
        ringbuf_entry!(Trace::StartTest(Test::Remain(remain)));
        if remain > 0 {
            let offset = len / Self::CHUNK_SIZE;
            self.attest
                .get_log_chunk(offset, &mut buf[..remain as usize]);
            ringbuf_entry!(Trace::Remain(remain));
        }
    }

    fn quote(&mut self, nonce: &[u8]) {
        ringbuf_entry!(Trace::StartTest(Test::QuoteLen));
        let len = self.attest.get_quote_len();
        ringbuf_entry!(Trace::QuoteLen(len));

        let mut buf = [0u8; Self::CHUNK_SIZE as usize];

        ringbuf_entry!(Trace::StartTest(Test::Quote));
        self.attest
            .get_quote(nonce, &mut buf[..len as usize])
    }
}

#[export_name = "main"]
fn main() {
    ringbuf_entry!(Trace::Start);

    let attest = AttestUtil::default();
    let mut test = AttestTest { attest };

    test.cert_chain();
    test.log();

    let mut rng = Rng::from(RNG.get_task_id());
    let mut nonce = [0u8; NONCE_SIZE];

    rng.try_fill_bytes(&mut nonce).unwrap_or_else(|e| {
        ringbuf_entry!(Trace::RngErr(e.into()));
        done();
    });
    let nonce = nonce;
    ringbuf_entry!(Trace::Nonce(nonce));

    test.quote(&nonce);

    done();
}
