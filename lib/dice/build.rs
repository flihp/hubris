// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dice_cert_tmpl::build_csr("csr.rs")?;
    dice_cert_tmpl::build_selfcert("cert-self.rs")?;
    dice_cert_tmpl::build_leafcert("cert-leaf.rs")?;

    Ok(())
}
