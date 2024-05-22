// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use idol::{server::ServerStyle, CounterSettings};
use std::{fs::File, io::Write};

mod config {
    include!("src/config.rs");
}

use config::DataRegion;

const CFG_SRC: &str = "rng-config.rs";

fn main() -> Result<()> {
    idol::Generator::new()
        .with_counters(CounterSettings::default().with_server_counters(false))
        .build_server_support(
            "../../idl/rng.idol",
            "server_stub.rs",
            ServerStyle::InOrder,
        )
        .map_err(|e| anyhow!(e))?;

    let out_dir = build_util::out_dir();
    let dest_path = out_dir.join(CFG_SRC);
    let mut out =
        File::create(dest_path).context(format!("creating {}", CFG_SRC))?;

    let data_regions = build_util::task_extern_regions::<DataRegion>()?;
    if data_regions.is_empty() {
        return Err(anyhow!("no data regions found"));
    }

    let region = data_regions
        .get("dice_rng")
        .ok_or_else(|| anyhow!("dice_rng data region not found"))?;
    writeln!(
        out,
        r##"use crate::config::DataRegion;
pub const RNG_DATA: DataRegion = DataRegion {{
    address: {:#x},
    size: {:#x},
}};"##,
        region.address, region.size
    )?;

    Ok(())
}
