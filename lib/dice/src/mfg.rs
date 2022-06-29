// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hubpack::SerializedSize;
use serde::{Deserialize, Serialize};

use crate::cert::DeviceIdCert;
use crate::csr::Csr;

// large variants in enum is intentional: this is how we do serialization
#[allow(clippy::large_enum_variant)]
#[derive(
    Clone, Copy, Debug, PartialEq, Deserialize, Serialize, SerializedSize,
)]
pub enum Msgs {
    CsrPlz,
    KThx,
    Csr(Csr),
    Cert(DeviceIdCert),
}

#[derive(
    Clone, Copy, Debug, PartialEq, Deserialize, Serialize, SerializedSize,
)]
pub struct Msg {
    pub id: u32,
    pub msg: Msgs,
}

impl Msg {
    pub const MAX_ENCODED_SIZE: usize =
        corncobs::max_encoded_len(Msg::MAX_SIZE);

    // from_encoded? from_corncobs? from_cob?
    pub fn from(data: &[u8]) -> Self {
        let mut buf = [0u8; Msg::MAX_SIZE];

        //TODO: expect
        let size = corncobs::decode_buf(data, &mut buf).expect("decode_buf");
        let (msg, _) =
            hubpack::deserialize::<Msg>(&buf[..size]).expect("deserialize");

        msg
    }

    pub fn encode(&self, dst: &mut [u8; Msg::MAX_ENCODED_SIZE]) -> usize {
        let mut buf = [0xFFu8; Msg::MAX_ENCODED_SIZE];

        //TODO: expect
        let size = hubpack::serialize(&mut buf, self).expect("serialize");

        corncobs::encode_buf(&buf[..size], dst)
    }
}
