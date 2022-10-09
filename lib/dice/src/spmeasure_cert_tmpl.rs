// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// NOTE: This DER blob, offsets & lengths are generated code. This
// is currently accomplished by an external tool:
// https://github.com/oxidecomputer/dice-util
// TODO: Generate cert templates in-tree.

use core::ops::Range;

pub const SIZE: usize = 631;
pub const SERIAL_NUMBER_RANGE: Range<usize> = 15..16;
pub const ISSUER_SN_RANGE: Range<usize> = 169..180;
pub const SUBJECT_SN_RANGE: Range<usize> = 361..372;
pub const PUB_RANGE: Range<usize> = 384..416;
pub const SIG_RANGE: Range<usize> = 567..631;
pub const SIGNDATA_RANGE: Range<usize> = 4..557;
pub const FWID_RANGE: Range<usize> = 525..557;
pub const CERT_TMPL: [u8; 631] = [
    0x30, 0x82, 0x02, 0x73, 0x30, 0x82, 0x02, 0x25, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30,
    0x81, 0x9a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61,
    0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0a, 0x45,
    0x6d, 0x65, 0x72, 0x79, 0x76, 0x69, 0x6c, 0x6c, 0x65, 0x31, 0x1f, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x16, 0x4f, 0x78, 0x69, 0x64,
    0x65, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43,
    0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x79, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
    0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63,
    0x74, 0x75, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x09, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d,
    0x69, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13,
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x20, 0x17, 0x0d, 0x32, 0x32, 0x31, 0x30, 0x30, 0x39, 0x30, 0x30,
    0x33, 0x32, 0x32, 0x35, 0x5a, 0x18, 0x0f, 0x39, 0x39, 0x39, 0x39, 0x31,
    0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81,
    0x9b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
    0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x0a, 0x45, 0x6d,
    0x65, 0x72, 0x79, 0x76, 0x69, 0x6c, 0x6c, 0x65, 0x31, 0x1f, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x16, 0x4f, 0x78, 0x69, 0x64, 0x65,
    0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x6f,
    0x6d, 0x70, 0x61, 0x6e, 0x79, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55,
    0x04, 0x0b, 0x0c, 0x0d, 0x4d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74,
    0x75, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x0a, 0x73, 0x70, 0x2d, 0x6d, 0x65, 0x61, 0x73, 0x75,
    0x72, 0x65, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13,
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa3, 0x81, 0x8a, 0x30,
    0x81, 0x87, 0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
    0x01, 0x86, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x18, 0x30,
    0x16, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x0c,
    0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x08, 0x30,
    0x40, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01, 0x01, 0x01, 0xff,
    0x04, 0x33, 0x30, 0x31, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x04, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x03, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
