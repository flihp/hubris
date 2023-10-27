// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use attest_api::{Attest, AttestError, Signature, SHA3_256_DIGEST_SIZE};
use drv_rng_api::{Rng, RngError};
use lib_dice::{AliasCert, Cert};
use rand_core::RngCore;
use ringbuf::{ringbuf, ringbuf_entry};
use salty::{Error as SaltyError, PublicKey, Signature as SaltySignature};
use sha3::{Digest as CryptDigest, Sha3_256};
use userlib::{task_slot, TaskId};
use zerocopy::FromBytes;

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
    Log,
    QuoteLen,
    Quote,
}

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    CertChainLen(u32),
    CertLen(u32),
    Chunk(u32),
    Deserialize,
    Remain(u32),
    Done,
    Error(AttestError),
    LogLen(u32),
    QuoteLen(u32),
    QuoteData([u8; SHA3_256_DIGEST_SIZE]),
    Signature(Signature),
    Nonce([u8; SHA3_256_DIGEST_SIZE]),
    None,
    Start,
    StartTest(Test),
    QuoteTooBig,
    RngErr(RngError),
    CertTooBig,
    NotSelfSigned,
    AliasCertLen(u32),
    SaltyError(SaltyError),
    BadPubKeySlice,
    QuoteVerified,
    Success,
}

ringbuf!(Trace, 32, Trace::None);

fn success() {
    ringbuf_entry!(Trace::Success);

    // wait for a signal from the kernel that will never come
    if userlib::sys_recv_closed(&mut [], 1, TaskId::KERNEL).is_err() {
        panic!();
    }
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
            panic!("AttestUtil::get_cert_chain_len");
        })
    }

    // get the length of the certificate at `index` position in the chain
    fn get_cert_len(&self, index: u32) -> u32 {
        self.attest.cert_len(index).unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            panic!("AttestUtil::get_cert_len");
        })
    }

    fn get_cert_chunk(&mut self, index: u32, offset: u32, chunk: &mut [u8]) {
        self.attest.cert(index, offset, chunk).unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            panic!("AttestUtil::get_cert_chunk");
        });
    }

    // get the certificate with length `len` at `index` position in the cert chain
    // NOTE: though we get the whole certificate we only have a 256 byte chunk of
    // it at a time
    fn get_cert(&mut self, index: u32, dst: &mut [u8]) -> u32 {
        let len = self.get_cert_len(index);
        if dst.len() < len as usize {
            ringbuf_entry!(Trace::CertTooBig);
            panic!("AttestUtil::get_cert");
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
            dst[offset as usize..(offset + remain) as usize]
                .copy_from_slice(&buf[..remain as usize]);
        }

        len
    }

    // get length of attestation measurement log
    fn get_log_len(&self) -> u32 {
        self.attest.log_len().unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            panic!("AttestUtil::get_log_len");
        })
    }

    fn get_log_chunk(&mut self, offset: u32, buf: &mut [u8]) {
        self.attest.log(offset, buf).unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            panic!("AttestUtil::get_log_chunk");
        });
    }

    fn get_log(&mut self, dst: &mut [u8]) -> u32 {
        let len = self.get_log_len();
        if dst.len() < len as usize {
            ringbuf_entry!(Trace::CertTooBig);
            panic!("AttestUtil::get_log");
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
            dst[offset as usize..(offset + remain) as usize]
                .copy_from_slice(&buf[..remain as usize]);
        }

        len
    }

    fn get_quote_len(&self) -> u32 {
        self.attest.quote_len().unwrap_or_else(|e| {
            ringbuf_entry!(Trace::Error(e));
            panic!("AttestUtil::get_quote_len");
        })
    }

    fn get_quote(&mut self, nonce: &[u8], dst: &mut [u8]) -> u32 {
        let len = self.get_quote_len();
        // quote must be read in one operation -> must fit in a single self.chunk
        if len as usize > dst.len() {
            ringbuf_entry!(Trace::QuoteTooBig);
            panic!("AttestUtil::get_quote");
        }

        self.attest
            .quote(nonce, &mut dst[..len as usize])
            .unwrap_or_else(|e| {
                ringbuf_entry!(Trace::Error(e));
                panic!("AttestUtil::get_quote");
            });

        len
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

    fn quote(&mut self, nonce: &[u8]) -> u32 {
        ringbuf_entry!(Trace::StartTest(Test::QuoteLen));
        let len = self.attest.get_quote_len();
        ringbuf_entry!(Trace::QuoteLen(len));

        let mut buf = [0u8; Self::CHUNK_SIZE as usize];

        ringbuf_entry!(Trace::StartTest(Test::Quote));
        self.attest.get_quote(nonce, &mut buf[..len as usize]);

        len
    }
}

// verifier for attestation from `Attest` task
// NOTE: We're only able to verify systems w/ self-signed persistent-id
// certs. See `dice-self` feature in lib/lpc55-rot-startup/Cargo.toml.
// This limitation is caused by our inability to get or parse the root cert
// when an proper PKI is used.
// NOTE: It's probably not worth verifying the cert chain here. That API can
// already be used over humility / hiffy & scripted w/ OpenSSL.
fn verify() {
    // GOAL: prove attestation is:
    // - authentic: quote_data signed by Alias_priv / verifies w/ Alias_pub
    // - fresh: attest_data construction includes nonce
    // - analyzable: attest_data can be reconstructed from measurement log
    //   & nonce
    //
    // DATA:
    // - log_data = hubpack_serialize(log)
    // - attest_digest = sha3_256(log_data | nonce)
    // - quote = sign(alias_priv, attest_data)
    //
    // STEPS:
    // - generate nonce
    let mut util = AttestUtil::default();
    let mut rng = Rng::from(RNG.get_task_id());
    let mut nonce = [0u8; NONCE_SIZE];

    rng.try_fill_bytes(&mut nonce).unwrap_or_else(|e| {
        ringbuf_entry!(Trace::RngErr(e.into()));
        panic!("rng.try_fill_bytes");
    });
    let nonce = nonce;
    ringbuf_entry!(Trace::Nonce(nonce));

    // - get quote_data, call `Attest::quote via AttestUtil::get_quote
    let mut quote_data = [0u8; (CHUNK_SIZE * 4) as usize];
    let quote_len = util.get_quote(&nonce, &mut quote_data);

    // - extract quote_data, check signature matches what's generated in the
    //   Attest task (verified)
    let (signature, _): (Signature, _) = hubpack::deserialize(
        &quote_data[..quote_len as usize],
    )
    .unwrap_or_else(|_| {
        ringbuf_entry!(Trace::Deserialize);
        panic!("verify");
    });
    ringbuf_entry!(Trace::Signature(signature));

    // - get log_data from `Attest::log`, reuse `quote_data` buffer
    let mut log_data = quote_data;
    let log_len = util.get_log(&mut log_data);
    let log_data = log_data;

    // - calculate attest_digest from log_data & nonce
    let mut hasher = Sha3_256::new();
    hasher.update(&log_data[..log_len as usize]);
    hasher.update(nonce);
    let attest_digest = hasher.finalize();
    ringbuf_entry!(Trace::QuoteData(attest_digest.into()));

    // - get alias cert: the leaf cert in the cert chain
    let cert_chain_len = util.get_cert_chain_len();
    ringbuf_entry!(Trace::CertChainLen(cert_chain_len));
    if cert_chain_len != 3 {
        ringbuf_entry!(Trace::NotSelfSigned);
        panic!("wrong cert chain len, not self signed?");
    }

    let mut alias_cert = log_data;
    let alias_cert_len = util.get_cert(0, &mut alias_cert);
    ringbuf_entry!(Trace::AliasCertLen(alias_cert_len));
    let alias_cert = alias_cert;

    // - get public key from alias cert & construct ed25519 verifier
    let alias_cert =
        AliasCert::read_from(&alias_cert[..alias_cert_len as usize])
            .unwrap_or_else(|| {
                ringbuf_entry!(Trace::Done);
                panic!("AliasCert::read_from");
            });
    
    let alias_pub = alias_cert.get_pub();
    let alias_pub: [u8; 32] = alias_pub.try_into().unwrap_or_else(|_| {
        ringbuf_entry!(Trace::BadPubKeySlice);
        panic!("pub_key try_into");
    });
    let alias_verifier = PublicKey::try_from(&alias_pub).unwrap_or_else(|e| {
        ringbuf_entry!(Trace::SaltyError(e));
        panic!("PublicKey::try_from");
    });

    // - verify quote_data from alias_pub, quote_data & attest_data
    match signature {
        Signature::Ed25519(sig) => {
            let sig = SaltySignature::from(&sig.0);
            alias_verifier
                .verify(&attest_digest, &sig)
                .unwrap_or_else(|e| {
                    ringbuf_entry!(Trace::SaltyError(e));
                    panic!("Signature verification failed");
            });
        },
    };
    ringbuf_entry!(Trace::QuoteVerified);
    // - verify cert chain (TBD) - probably not worth doing here since we can
    //   already do this by scripting hiffy / humility
}

// exercise the Attest task / Attest::* interface
fn use_interface() {
    let attest = AttestUtil::default();

    let mut test = AttestTest { attest };

    test.cert_chain();
    test.log();

    let nonce = [0u8; NONCE_SIZE];
    test.quote(&nonce);
}

#[export_name = "main"]
fn main() {
    ringbuf_entry!(Trace::Start);

    use_interface();
    verify();

    success();
}
