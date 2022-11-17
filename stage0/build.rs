// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = build_util::out_dir();
    let mut const_file = File::create(out.join("consts.rs")).unwrap();

    let image_id: u64 = build_util::env_var("HUBRIS_IMAGE_ID")?.parse()?;

    writeln!(const_file, "// See build.rs for details")?;

    writeln!(const_file, "#[used]")?;
    writeln!(const_file, "#[no_mangle]")?;
    writeln!(const_file, "#[link_section = \".hubris_id\"]")?;
    writeln!(
        const_file,
        "pub static HUBRIS_IMAGE_ID: u64 = {};",
        image_id
    )?;

    #[cfg(feature = "dice-mfg")]
    gen_memory_range(&out)?;

    Ok(())
}

#[cfg(feature = "dice-mfg")]
fn gen_memory_range (
    out_dir: &std::path::PathBuf
) -> Result<(), Box<dyn std::error::Error>> {
    use serde::Deserialize;
    use std::collections::HashMap;

    #[derive(Deserialize, Debug)]
    struct Region {
        pub name: String,
        pub address: u32,
        pub size: u32,
    }

    // get this from the env set by xtask
    let memory = "[[flash]]\nname = \"dice\"\naddress = 0x90000\nsize = 0x800\nread = true\nwrite = true\nexecute = false\n";
    let memory: HashMap<String, Vec<Region>> = toml::from_str(memory)?;
    let flash = match memory.get("flash") {
        Some(out) => out,
        None => {
            return Err("key not in memory array: \"flash\", can't build stage0")?;
        }
    };
    // find flash array of tables for region with name = "dice"
    let dice_mem = flash
        .iter()
        .filter(|r| &r.name == "dice")
        .next()
        .expect("no memory region with name \"dice\"");

    let mut file = File::create(out_dir.join("memory.rs")).unwrap();
    writeln!(file,
             "use core::ops::Range;\n\n\
             pub const DICE_FLASH: Range<usize> = {}..{};",
             dice_mem.address, dice_mem.address + dice_mem.size)?;

    Ok(())
}
