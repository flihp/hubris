// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use build_util;
use std::{env, error::Error, io::Write};

fn main() -> Result<(), Box<dyn Error>> {
    let out_dir = build_util::out_dir();
    let dest_path = out_dir.join("env.txt");
    let mut file = std::fs::File::create(&dest_path)?;

    for (key, value) in env::vars() {
        if key.starts_with("HUBRIS_") {
            writeln!(&mut file, "{key}: {value}")?;
        }
    }

    Ok(())
}
