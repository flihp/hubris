// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Driver for the LPC55 random number generator.
//!
//! Use the rng-api crate to interact with this driver.

#![no_std]
#![no_main]

mod config;

use core::{cmp, usize};
use drv_lpc55_syscon_api::Syscon;
use drv_rng_api::RngError;
use idol_runtime::{ClientError, NotificationHandler, RequestError};
use lib_dice::{persistid_cert_tmpl::SUBJECT_CN_LENGTH, RngSeed, SeedBuf};
use lib_lpc55_rng::Lpc55Rng;
use lpc55_pac::Peripherals;
use rand_chacha::ChaCha20Rng;
use rand_core::{impls, Error, RngCore, SeedableRng};
use ringbuf::ringbuf;
use sha3::{
    digest::crypto_common::{generic_array::GenericArray, OutputSizeUser},
    digest::FixedOutputReset,
    Digest, Sha3_256,
};
use userlib::task_slot;
use zeroize::Zeroizing;

cfg_if::cfg_if! {
    if #[cfg(feature = "dice-seed")] {
        use config::DataRegion;
        use hubpack::SerializedSize;
        use lib_dice::{persistid_cert_tmpl::SUBJECT_CN_RANGE, CertData, RngData};
        use ringbuf::ringbuf_entry;
        use serde::Deserialize;
        use stage0_handoff::{HandoffData, HandoffDataLoadError};
        use userlib::UnwrapLite;

        // This file is generated by the crate build.rs. It contains instances
        // of config::DataRegion structs describing regions of memory
        // configured & exposed to this task by the hubris build.
        mod build {
            include!(concat!(env!("OUT_DIR"), "/rng-config.rs"));
        }

        use build::{DICE_CERTS, DICE_RNG};
    }
}

task_slot!(SYSCON, syscon_driver);

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    None,
    #[cfg(feature = "dice-seed")]
    NoDiceSeed,
    #[cfg(feature = "dice-seed")]
    HandoffError(HandoffDataLoadError),
    #[cfg(feature = "dice-seed")]
    NoSeedPersonalization,
}

ringbuf!(Trace, 16, Trace::None);

// low-budget rand::rngs::adapter::ReseedingRng w/o fork stuff
struct ReseedingRng<T: SeedableRng, R: RngCore, H: Digest> {
    inner: T,
    reseeder: R,
    threshold: usize,
    bytes_until_reseed: usize,
    mixer: H,
    output: [u8; 32],
}

impl<T, R, H> ReseedingRng<T, R, H>
where
    T: SeedableRng<Seed = [u8; 32]> + RngCore,
    R: RngCore,
    H: FixedOutputReset + Default + Digest,
    GenericArray<u8, <H as OutputSizeUser>::OutputSize>: From<[u8; 32]>,
{
    fn new(
        seed: Option<&RngSeed>,
        mut reseeder: R,
        pid: Option<&[u8; SUBJECT_CN_LENGTH]>,
        threshold: usize,
    ) -> Result<Self, Error> {
        let threshold = if threshold == 0 {
            usize::MAX
        } else {
            threshold
        };

        let mut mixer = H::default();
        if let Some(seed) = seed {
            // mix platform unique seed derived by measured boot
            Digest::update(&mut mixer, seed.as_bytes());
        }

        if let Some(pid) = pid {
            // mix in unique platform id
            Digest::update(&mut mixer, pid);
        }

        // w/ 32 bytes from HRNG
        let mut buf = Zeroizing::new(T::Seed::default());
        reseeder.try_fill_bytes(buf.as_mut())?;
        Digest::update(&mut mixer, buf.as_ref());

        // create initial instance of the SeedableRng from the seed
        let output = [0u8; 32];
        Digest::finalize_into_reset(&mut mixer, &mut output.into());
        let inner = T::from_seed(output.into());

        Ok(ReseedingRng {
            inner,
            reseeder,
            threshold,
            bytes_until_reseed: threshold,
            mixer,
            output,
        })
    }
}

impl<T, R, H> RngCore for ReseedingRng<T, R, H>
where
    T: SeedableRng<Seed = [u8; 32]> + RngCore,
    R: RngCore,
    H: FixedOutputReset + Default + Digest,
    GenericArray<u8, <H as OutputSizeUser>::OutputSize>: From<[u8; 32]>,
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
        let mut filled = 0;

        while filled < dest.len() {
            if self.bytes_until_reseed > 0 {
                // fill dest as much as we can
                let len =
                    cmp::min(dest.len() - filled, self.bytes_until_reseed);
                self.inner.try_fill_bytes(&mut dest[filled..filled + len])?;

                filled += len;
                self.bytes_until_reseed -= len;
            } else {
                // create seed for next PRNG & reset mixer
                let mut buf = Zeroizing::new(T::Seed::default());

                // mix 32 bytes from current PRNG instance
                self.inner.try_fill_bytes(buf.as_mut())?;
                Digest::update(&mut self.mixer, buf.as_mut());

                // w/ 32 bytes from HRNG
                self.reseeder.try_fill_bytes(buf.as_mut())?;
                Digest::update(&mut self.mixer, buf.as_mut());

                // seed new RNG instance & reset mixer
                Digest::finalize_into_reset(
                    &mut self.mixer,
                    &mut self.output.into(),
                );
                self.inner = T::from_seed(self.output.into());

                // reset reseed countdown
                self.bytes_until_reseed = self.threshold;
            }
        }

        Ok(())
    }
}

struct Lpc55RngServer(ReseedingRng<ChaCha20Rng, Lpc55Rng, Sha3_256>);

impl Lpc55RngServer {
    fn new(
        seed: Option<&RngSeed>,
        reseeder: Lpc55Rng,
        pid: Option<&[u8; SUBJECT_CN_LENGTH]>,
        threshold: usize,
    ) -> Result<Self, Error> {
        Ok(Lpc55RngServer(ReseedingRng::new(
            seed, reseeder, pid, threshold,
        )?))
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

/// Load a type implementing HandoffData (and others) from a config::DataRegion.
/// Errors will be reported in the ringbuf and will return None.
#[cfg(feature = "dice-seed")]
fn load_data_from_region<
    T: for<'a> Deserialize<'a> + HandoffData + SerializedSize,
>(
    region: &DataRegion,
) -> Option<T> {
    use core::slice;

    // Safety: This memory is setup by code executed before hubris and
    // exposed using the kernel `extern-regions` mechanism. The safety of
    // this code is an extension of our trust in the hubris pre-main, kernel,
    // and build process.
    let data = unsafe {
        slice::from_raw_parts(region.address as *mut u8, region.size)
    };

    T::load_from_addr(data)
        .inspect_err(|e| ringbuf_entry!(Trace::HandoffError(*e)))
        .ok()
}

/// Get the seed derived by the lpc55-rot-startup and passed to us through
/// the stage0-handoff memory region.
///
/// If use of DICE seed in seeding the PRNG is not enabled then this function
/// will just return None. Otherwise it will attempt to get the seed from the
/// dice-rng region of the stage0-handoff memory. If it's not able to get
/// the seed it will put an entry in the ringbuf and panic.
pub fn get_dice_seed() -> Option<RngSeed> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "dice-seed")] {
            match load_data_from_region::<RngData>(&DICE_RNG) {
                Some(rng_data) => Some(rng_data.seed),
                _ => {
                    ringbuf_entry!(Trace::NoDiceSeed);
                    panic!();
                },
            }
        } else {
            None
        }
    }
}

/// Get the platform identifier / barcode string from the platform identity
/// cert passed to hubris by the lpc55-rot-startup through the stage0-handoff
/// memory region.
///
/// If use of the platform identifier string is not enabled then this function
/// will return `None`. Otherwise it will try to get the platform identity
/// string from the stage0-handoff region. If it's unable to get this data it
/// will put an entry into the ringbuf and panic.
pub fn get_seed_personalization() -> Option<[u8; SUBJECT_CN_LENGTH]> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "dice-seed")] {
            match load_data_from_region::<CertData>(&DICE_CERTS) {
                 Some(cert_data) => Some(
                     cert_data.persistid_cert.0.as_bytes()[SUBJECT_CN_RANGE]
                         .try_into()
                         .unwrap_lite(),
                 ),
                _ => {
                    ringbuf_entry!(Trace::NoSeedPersonalization);
                    panic!();
                },
            }
        } else {
            None
        }
    }
}

#[export_name = "main"]
fn main() -> ! {
    let seed = get_dice_seed();
    let pid = get_seed_personalization();
    let peripherals = Peripherals::take().unwrap();

    let rng = Lpc55Rng::new(
        peripherals.PMC,
        peripherals.RNG,
        &Syscon::from(SYSCON.get_task_id()),
    );

    let threshold = 0x100000; // 1 MiB
    let mut rng =
        Lpc55RngServer::new(seed.as_ref(), rng, pid.as_ref(), threshold)
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
