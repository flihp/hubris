// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]
#![no_main]

use null_api::Null;
use ringbuf::{ringbuf, ringbuf_entry};
use userlib::{task_slot, TaskId};

#[derive(Copy, Clone, PartialEq)]
enum Trace {
    CallingArrayInZerocopy([u8; 4]),
    CallingArrayInHubpack([u8; 4]),
    CallingNull,
    None,
    Start,
    Success,
}

ringbuf!(Trace, 16, Trace::None);

task_slot!(NULL, null_server);

#[export_name = "main"]
fn main() {
    ringbuf_entry!(Trace::Start);

    let null = Null::from(NULL.get_task_id());

    ringbuf_entry!(Trace::CallingNull);
    null.null().unwrap();
    ringbuf_entry!(Trace::Success);

    let array = [0xbe, 0xef, 0xde, 0xad];
    ringbuf_entry!(Trace::CallingArrayInZerocopy(array));
    null.array_in_zerocopy(array).unwrap();
    ringbuf_entry!(Trace::Success);

    let array = [0xde, 0xad, 0xbe, 0xef];
    ringbuf_entry!(Trace::CallingArrayInHubpack(array));
    null.array_in_hubpack(array).unwrap();
    ringbuf_entry!(Trace::Success);

    if userlib::sys_recv_closed(&mut [], 1, TaskId::KERNEL).is_err() {
        panic!();
    }
}
