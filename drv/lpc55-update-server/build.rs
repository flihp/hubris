// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use std::fs::File;
use std::io::Write;

mod config {
    include!("src/config.rs");
}

use config::DataRegion;

fn main() -> Result<()> {
    build_util::expose_target_board();
    build_util::build_notifications()?;

    idol::server::build_server_support(
        "../../idl/lpc55-update.idol",
        "server_stub.rs",
        idol::server::ServerStyle::InOrder,
    )
    .unwrap();

    let out = build_util::out_dir();
    let mut ver_file = File::create(out.join("consts.rs")).unwrap();

    let version: u32 = build_util::env_var("HUBRIS_BUILD_VERSION")?.parse()?;
    let epoch: u32 = build_util::env_var("HUBRIS_BUILD_EPOCH")?.parse()?;

    writeln!(ver_file, "const HUBRIS_BUILD_VERSION: u32 = {};", version)?;
    writeln!(ver_file, "const HUBRIS_BUILD_EPOCH: u32 = {};", epoch)?;

    let data_regions = build_util::task_extern_regions::<DataRegion>()?;
    if data_regions.is_empty() {
        return Err(anyhow::anyhow!("no data regions found"));
    }

    let region = data_regions
        .get("usbsram")
        .ok_or_else(|| anyhow::anyhow!("dice_certs data region not found"))?;
    writeln!(
        ver_file,
        r##"
pub const BOOTSTATE: DataRegion = DataRegion {{
    address: {:#x},
    size: {:#x},
}};"##,
        region.address, region.size
    )?;

    Ok(())
}
