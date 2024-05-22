// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Driver for the LPC55 random number generator.
//!
//! Use the rng-api crate to interact with this driver.

#![no_std]
#![no_main]

use core::{cmp, usize};
use drv_lpc55_syscon_api::Syscon;
use drv_rng_api::RngError;
use idol_runtime::{ClientError, NotificationHandler, RequestError};
use lib_lpc55_rng::Lpc55Rng;
use rand_chacha::ChaCha20Rng;
use rand_core::{impls, Error, RngCore, SeedableRng};
use ringbuf::{ringbuf, ringbuf_entry};
use sha3::{Digest, digest::FixedOutputReset, Sha3_256};
use userlib::*;

task_slot!(SYSCON, syscon_driver);

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    FillingBytes(usize),
    Recurse(usize, usize),
    Reseed,
    ReseedingFill(usize),
    None,
}

ringbuf!(Trace, 16, Trace::None);

// low-budget rand::rngs::adapter::ReseedingRng w/o fork stuff
struct ReseedingRng<T: SeedableRng, R: RngCore> {
    inner: T,
    rng: R,
    threshold: usize,
    bytes_until_reseed: usize,
    mixer: Sha3_256,
}

const RNG_BYTE_COUNT: usize = 1024;
const RNG_BUF_SIZE: usize = 32;

impl<T, R> ReseedingRng<T, R>
where
    T: SeedableRng<Seed = [u8; 32]> + RngCore,
    R: RngCore,
{
    fn new(
        mut rng: R,
        threshold: usize,
    ) -> Result<Self, Error> {
        use ::core::usize::MAX;

        let threshold = if threshold == 0 { MAX } else { threshold };

        // create initial seed for inner SeedableRng
        let mut mixer = Sha3_256::default();

        // roll RNG_BUF_SIZE bytes from the HRNG into the seed
        let mut bytes = [0u8; RNG_BUF_SIZE];
        for _ in 0..(RNG_BYTE_COUNT / RNG_BUF_SIZE) {
            rng.try_fill_bytes(&mut bytes)?;
            mixer.update(bytes);
        }

        // create initial instance of the SeedableRng from the seed
        let inner = T::from_seed(mixer.finalize_fixed_reset().into());

        Ok(ReseedingRng {
            inner,
            rng,
            threshold,
            bytes_until_reseed: threshold,
            mixer,
        })
    }

    /// Reseed the inner PRNG
    fn reseed(&mut self) -> Result<(), Error> {
        ringbuf_entry!(Trace::Reseed);

        let mut buf = [0u8; RNG_BUF_SIZE];

        // mix 32 bytes from current RNG instance
        self.inner.try_fill_bytes(&mut buf)?;
        // NOTE: this could be a foot gun if someone leaves crap in the mixer
        // ... maybe best to reset it before using it.
        let _ = self.mixer.finalize_fixed_reset();
        self.mixer.update(buf);

        // w/ another 1k from rng
        for _ in 0..(RNG_BYTE_COUNT / RNG_BUF_SIZE){
            self.rng.try_fill_bytes(&mut buf)?;
            self.mixer.update(buf);
        }

        // seed new RNG instance
        self.inner = T::from_seed(self.mixer.finalize_fixed_reset().into());

        // reset threshold for next reseed
        self.bytes_until_reseed = self.threshold;

        Ok(())
    }
}

impl<T, R> RngCore for ReseedingRng<T, R>
where
    T: SeedableRng<Seed = [u8; 32]> + RngCore,
    R: RngCore,
{
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("Failed to get entropy from RNG.")
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let num_bytes = dest.len();
        ringbuf_entry!(Trace::ReseedingFill(num_bytes));

        if num_bytes < self.bytes_until_reseed {
            // Terminal condition: we can service the request w/o reseeding.
            ringbuf_entry!(Trace::FillingBytes(num_bytes));
            self.bytes_until_reseed -= num_bytes;
            self.inner.try_fill_bytes(dest)
        } else {
            // We've been asked for bytes that exceed the reseed threshold:
            // - fill the buffer up to the threshold
            // - reseed
            // - make a recursive call to fill the rest
            ringbuf_entry!(Trace::FillingBytes(self.bytes_until_reseed));
            self.inner
                .try_fill_bytes(&mut dest[..self.bytes_until_reseed])?;
            self.reseed()?;
            ringbuf_entry!(Trace::Recurse(self.bytes_until_reseed, num_bytes));
            self.try_fill_bytes(&mut dest[self.bytes_until_reseed..])
        }
    }
}

struct Lpc55RngServer(ReseedingRng<ChaCha20Rng, Lpc55Rng>);

impl Lpc55RngServer {
    fn new(
        rng: Lpc55Rng,
        threshold: usize,
    ) -> Result<Self, Error> {
        Ok(Lpc55RngServer(ReseedingRng::new(rng, threshold)?))
    }
}

impl idl::InOrderRngImpl for Lpc55RngServer {
    fn fill(
        &mut self,
        _: &userlib::RecvMessage,
        dest: idol_runtime::Leased<idol_runtime::W, [u8]>,
    ) -> Result<usize, RequestError<RngError>> {
        let mut cnt = 0;
        let mut buf = [0u8; 32];
        while cnt < dest.len() {
            let len = cmp::min(buf.len(), dest.len() - cnt);

            self.0
                .try_fill_bytes(&mut buf[..len])
                .map_err(RngError::from)?;
            dest.write_range(cnt..cnt + len, &buf[..len])
                .map_err(|_| RequestError::Fail(ClientError::WentAway))?;

            cnt += len;
        }

        Ok(cnt)
    }
}

impl NotificationHandler for Lpc55RngServer {
    fn current_notification_mask(&self) -> u32 {
        // We don't use notifications, don't listen for any.
        0
    }

    fn handle_notification(&mut self, _bits: u32) {
        unreachable!()
    }
}

#[export_name = "main"]
fn main() -> ! {
    let rng = Lpc55Rng::new();
    rng.init(&Syscon::from(SYSCON.get_task_id()))
        .expect("Lpc55Rng::init failed");

    let threshold = 0x100000; // 1 MiB

    let mut rng = Lpc55RngServer::new(rng, threshold)
        .expect("Failed to create Lpc55RngServer");
    let mut buffer = [0u8; idl::INCOMING_SIZE];

    loop {
        idol_runtime::dispatch(&mut buffer, &mut rng);
    }
}

mod idl {
    use drv_rng_api::RngError;

    include!(concat!(env!("OUT_DIR"), "/server_stub.rs"));
}
