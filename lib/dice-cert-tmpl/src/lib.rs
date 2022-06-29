// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod cert;

use crate::cert::Cert;

use salty::constants::{
    PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH,
};
use std::{env, error::Error, fs::File, io::Write, path::PathBuf};

pub const ED25519_PUB_LEN: usize = PUBLICKEY_SERIALIZED_LENGTH;
pub const ED25519_SIG_LEN: usize = SIGNATURE_SERIALIZED_LENGTH;
// TODO: get this programatically from the cert / csr
pub const SN_LEN: usize = 12;

/// This function should be called from a build.rs in hubris. It generates a
/// source file that includes:
/// - a template for a self signed certificate intended for use as a DeviceId
///   cert (reference)
/// - constant offsets into this template used to populate fields turning the
///   template into a proper certificate
///
/// `cert_path` is to a cert that meets the assumptions made in this crate.
/// `out_name` is the path to the file generated.
pub fn build_selfcert(out_name: &str) -> Result<(), Box<dyn Error>> {
    let mut cert = *include_bytes!("../data/deviceid-selfcert-tmpl.der");
    let mut cert = Cert::from_slice(&mut cert);

    let out_path =
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(out_name);
    let mut out_file = File::create(&out_path).expect("file create");

    cert_write_common_indexes(&mut cert, &mut out_file)?;
    cert_write_trailer(&mut cert, &mut out_file)?;

    call_rustfmt::rustfmt(&out_path)?;

    Ok(())
}

/// This function should be called from a build.rs in hubris. It generates a
/// source file that includes:
/// - a template for a leaf certificate intended for use as an Alias cert
///   (reference)
/// - constant offsets into this template used to populate fields turning the
///   template into a proper certificate
/// NOTE: The primary distinction between 'build_leafcert' and 'build_selfcert'
/// is that the leafcert has the tcg-dice-TcbInfo structure and so we must
/// create the offsets to set the FWID field.
pub fn build_leafcert(out_name: &str) -> Result<(), Box<dyn Error>> {
    let mut cert = *include_bytes!("../data/alias-cert-tmpl.der");
    let mut cert = Cert::from_slice(&mut cert);

    let out_path =
        PathBuf::from(env::var_os("OUT_DIR").unwrap()).join(out_name);
    let mut out_file = File::create(&out_path).expect("file create");

    cert_write_common_indexes(&mut cert, &mut out_file)?;

    // certs descendent from the DeviceId have the FWID field
    let (start, end) = cert.get_fwid_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const FWID_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const FWID_END: usize = {};",
        end
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const FWID_LENGTH: usize = {};",
        end - start
    )?;

    cert_write_trailer(&mut cert, &mut out_file)?;

    call_rustfmt::rustfmt(&out_path)?;

    Ok(())
}

/// Write out the final cert and the function used by consumers to copy the
/// template.
fn cert_write_trailer(
    cert: &mut Cert,
    out_file: &mut File,
) -> Result<(), Box<dyn Error>> {
    buf_out(out_file, "CERT_TMPL", cert.as_bytes())?;

    writeln!(
        out_file,
        "#[allow(dead_code)]\npub fn fill(cert: &mut [u8; {}]) {{",
        cert.len()
    )?;
    writeln!(out_file, "cert.copy_from_slice(&CERT_TMPL);}}")?;

    Ok(())
}

fn cert_write_common_indexes(
    cert: &mut Cert,
    out_file: &mut File,
) -> Result<(), Box<dyn Error>> {
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SIZE: usize = {};",
        cert.len()
    )?;

    let (start, end) = cert.get_serial_number_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SERIAL_NUMBER_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SERIAL_NUMBER_END: usize = {};",
        end
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_issuer_sn_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const ISSUER_SN_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const ISSUER_SN_END: usize = {};",
        end
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SN_LENGTH: usize = {};",
        end - start
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_notbefore_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const NOTBEFORE_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const NOTBEFORE_END: usize = {};",
        end
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const NOTBEFORE_LENGTH: usize = {};",
        end - start
    )?;

    // get current date / time, set as notBefore
    use chrono::prelude::{DateTime, Utc};

    let utc: DateTime<Utc> = Utc::now();
    let utc = utc.format("%y%m%d%H%M%SZ").to_string();
    cert.set_range(start, utc.as_bytes());

    let (start, end) = cert.get_subject_sn_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SUBJECT_SN_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SUBJECT_SN_END: usize = {};",
        end
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_pub_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const PUB_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const PUB_END: usize = {};",
        end
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_sig_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SIG_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SIG_END: usize = {};",
        end
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_signdata_offsets()?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SIGNDATA_START: usize = {};",
        start
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SIGNDATA_END: usize = {};",
        end
    )?;
    writeln!(
        out_file,
        "#[allow(dead_code)]\npub const SIGNDATA_LENGTH: usize = {};",
        end - start
    )?;

    Ok(())
}

/// Write the supplied buffer as a const with the given name.
fn buf_out<F: Write>(
    out: &mut F,
    name: &str,
    slice: &[u8],
) -> Result<(), Box<dyn Error>> {
    writeln!(out, "const {}: [u8; {}] = [", name, slice.len())?;
    for elm in slice.iter() {
        write!(out, "{:#04x}, ", elm)?;
    }
    writeln!(out, "];")?;
    Ok(())
}
