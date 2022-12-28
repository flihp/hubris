// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dice_crate::SeedBuf;
use salty::constants::SECRETKEY_SEED_LENGTH;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Number of u32s in the KeyCode for a SEED_LEN key.
pub const KEYCODE_LEN: usize = 13;
// Number of bytes in the "key" generated. We use these bytes as the seed
// for an ed25519 keypair.
pub const SEED_LEN: usize = SECRETKEY_SEED_LENGTH;
const KEY_INDEX: u32 = 1;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PersistIdSeed([u8; SEED_LEN]);

impl PersistIdSeed {
    pub fn new(seed: [u8; SEED_LEN]) -> Self {
        Self(seed)
    }
}

impl SeedBuf for PersistIdSeed {
    fn as_bytes(&self) -> &[u8; SEED_LEN] {
        &self.0
    }
}

// Set key index (between 0 & 15) for a key generated by the PUF or set
// through the API. This value is ignored for the GetKey command as the index
// is baked into the KeyCode.
// NOTE: The only use for the key index is to send keys to hardware blocks
// like the AES & PRINCE hardware (key index 0). Any key index != 0 is fine
// for our purposes.
fn set_key_index(puf: &lpc55_pac::PUF, index: u32) -> bool {
    if index > 15 {
        return false;
    }

    // SAFETY: The PAC crate can't prevent us from setting the reserved
    // bits (the top 28) so this interface is unsafe. We ensure safety by
    // making index an unsigned type and the check above.
    puf.keyindex.write(|w| unsafe { w.bits(index) });

    true
}

// Set the size (in bytes) of the key generated by the PUF or set through
// the API. Ths value is ignored for the GetKey command as the key size is
// baked into the KeyCode.
fn set_key_size(puf: &lpc55_pac::PUF, size: usize) -> bool {
    let size: u32 = ((size * 8) >> 6).try_into().unwrap();
    if size < 32 {
        // SAFETY: The PAC crate can't prevent us from setting the reserved
        // bits (the top 27) so this interface is unsafe. We ensure safety
        // by using  the type system (index is an unsigned type) and the
        // check above.
        puf.keysize.write(|w| unsafe { w.bits(size) });

        true
    } else {
        return false;
    }
}

// wait for puf to accept last command submitted
fn wait_for_cmd_accept(puf: &lpc55_pac::PUF) -> bool {
    // cmd has been accepted if either the PUF becomes busy or there's an error
    while !is_busy(puf) && !is_error(puf) {}

    // if there was an error the cmd was rejected
    if !puf.stat.read().error().bit() {
        true
    } else {
        false
    }
}

fn is_busy(puf: &lpc55_pac::PUF) -> bool {
    puf.stat.read().busy().bit()
}

fn is_error(puf: &lpc55_pac::PUF) -> bool {
    puf.stat.read().error().bit()
}

fn is_success(puf: &lpc55_pac::PUF) -> bool {
    puf.stat.read().success().bit()
}

// execute PUF GenerateKey command, keycode is returned through second param
// length in bytes
pub fn generate_seed(puf: &lpc55_pac::PUF) -> [u32; KEYCODE_LEN] {
    let mut keycode = [0u32; KEYCODE_LEN];
    // GenerateKey can't be explicitly disallowed but it's covered by the
    // AllowSetKey.
    if !puf.allow.read().allowsetkey().bit() {
        panic!("DenySetKey");
    }

    // set parameters
    set_key_size(puf, SEED_LEN);
    set_key_index(puf, KEY_INDEX);

    // execute GenerateKey function / set GENERATEKEY bit in CTRL register
    puf.ctrl.write(|w| w.generatekey().set_bit());
    if !wait_for_cmd_accept(puf) {
        panic!("PufCmdAccept");
    }

    // while PUF is busy, read out whatever part of the KC is available
    let mut idx = 0;
    while is_busy(puf) {
        if idx > keycode.len() - 1 {
            panic!("PufKCTooLong");
        }
        if puf.stat.read().codeoutavail().bit() {
            let keycode_part = puf.codeoutput.read().bits();
            keycode[idx] = keycode_part;
            idx += 1;
        }
    }

    keycode
}

// execute PUF GetKey command, key is returned through third param
// TODO: this looks a lot like the constructor for PersistIdSeed?
pub fn get_seed(
    puf: &lpc55_pac::PUF,
    keycode: &[u32; KEYCODE_LEN],
) -> [u8; SEED_LEN] {
    if !puf.allow.read().allowgetkey().bit() {
        panic!("DenyGetKey");
    }

    // execute CTRL function / set GETKEY bit in CTRL register, no params
    puf.ctrl.write(|w| w.getkey().set_bit());

    wait_for_cmd_accept(puf);

    let mut key = [0u8; SEED_LEN];
    let mut kc_idx = 0;
    let mut key_idx = 0;
    // while PUF busy ... error detection?
    while is_busy(puf) && !is_error(puf) {
        if puf.stat.read().codeinreq().bit() {
            puf.codeinput.write(|w| unsafe { w.bits(keycode[kc_idx]) });
            kc_idx += 1;
        }
        if puf.stat.read().keyoutavail().bit() {
            for byte in puf.keyoutput.read().bits().to_ne_bytes() {
                key[key_idx] = byte;
                key_idx += 1;
            }
        }
    }

    if !is_success(puf) {
        panic!("PufFail");
    }

    key
}
