// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use build_util;
use serde::Deserialize;
use std::{collections::HashMap, error::Error, fs::File, io::Write, ops::Range};

#[derive(Deserialize, Debug)]
struct Region {
    pub address: u32,
    pub size: u32,
}

fn main() -> Result<(), Box<dyn Error>> {
    // need to get this from xtask: it's a peripheral not currently in chips.tmol
    let periph_range: Range<usize> = 0x4010_0000..0x4010_4000;
    // need to get this from xtask: not peripherals but currently in chips.toml
    let toml = "[dice_certs]\naddress = 0x40100000\nsize = 0x800\n\n \
                [dice_alias]\naddress = 0x40100800\nsize = 0x800\n\n \
                [dice_spmeasure]\naddress = 0x40101000\nsize = 0x800\n\n \
                [dice_rng]\naddress = 0x40101800\nsize = 0x100\n\n \
                [foo_region]\naddress = 0xdeadbeef\nsize = 0xf100f";
    // sort on address
    let regions: HashMap<String, Region> = toml::from_str(toml)?;

    let mut regions: Vec<(&String, &Region)> = regions.iter().collect();
    regions.sort_by(|a, b| a.1.address.cmp(&b.1.address));

    let out_dir = build_util::out_dir();
    let dest_path = out_dir.join("regions.rs");
    let mut region_file = File::create(&dest_path)?;

    // this is a generic way to generate ranges for chip.toml entries prefixed
    // with 'dice_' incompatible changes in chip.toml will result in failure
    // to compile the handoff code
    // if we pull the regions we're expecting from the map manually we can give
    // better error output at the expense of more code
    let mut end: usize = periph_range.start;
    writeln!(region_file, "// generated by lib/dice/build.rs")?;
    let mut start: usize;
    for (name, region) in regions {
        match name.strip_prefix("dice_") {
            Some(n) => {
                writeln!(
                    region_file,
                    "pub const {}_RANGE: core::ops::Range<usize> = {}..{};",
                    n.to_uppercase(), region.address, region.address + region.size
                )?;
                // this generates ugly code but it's functional and correct:
                // memory addresses are used in static assertions, not start /
                // end member data from the ranges
                // maybe use strings for REGION_NAME.start?
                start = region.address as usize;
                writeln!(
                    region_file,
                    "static_assertions::const_assert!({} <= {});",
                    end, start
                )?;
                end = (region.address + region.size) as usize;
            }
            None => continue,
        };
    }
    start = periph_range.end;
    writeln!(
        region_file,
        "static_assertions::const_assert!({} <= {});",
        end, start)?;

    Ok(())
}
