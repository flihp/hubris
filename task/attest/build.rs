// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use idol::server::{self, ServerStyle};
use serde::Deserialize;
use std::{fs::File, io::Write};

#[derive(Deserialize, Default, Debug)]
#[serde(rename_all = "kebab-case")]
struct DataRegion {
    pub address: u32,
    pub size: u32,
}

fn main() -> Result<()> {
    server::build_server_support(
        "../../idl/attest.idol",
        "server_stub.rs",
        ServerStyle::InOrder,
    ).unwrap();

    let out_dir = build_util::out_dir();
    let dest_path = out_dir.join("attest_config.rs");
    let mut out = File::create(dest_path).context("creating attest_config.rs")?;

    let data_regions = build_util::task_extern_regions::<DataRegion>()?;
    if data_regions.is_empty() {
        return Err(anyhow::anyhow!("attest task missing required data regions"));
    }

    let region = data_regions.get("dice_alias").ok_or(anyhow::anyhow!("dice_alias data region not found"))?;
    writeln!(
        out,
r##"const ALIAS_DATA: DataRegion = DataRegion {{
    address: {:#x},
    size: {:#x},
}};"##,
        region.address,
        region.size
    )?;

    let region = data_regions.get("dice_certs").ok_or(anyhow::anyhow!("dice_alias data region not found"))?;
    writeln!(
        out,
r##"const CERT_DATA: DataRegion = DataRegion {{
    address: {:#x},
    size: {:#x},
}};"##,
        region.address,
        region.size
    )?;

    Ok(())
}
