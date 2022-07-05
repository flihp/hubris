use dice_cert_tmpl::cert::Cert;
use std::error;

/// Tool to dump tbsCertificate from cert. This is the data that gets signed
/// by the device id cert.
fn main() -> Result<(), Box<dyn error::Error>> {
    let der = include_bytes!("../../data/deviceid-selfcert-tmpl.der");
    let mut der = *der;

    let cert = Cert::from_slice(&mut der);
    let (start, end) = cert.get_signdata_offsets().expect("fml");

    for (index, byte) in cert.as_bytes()[start..end].iter().enumerate() {
        if index % 12 == 11 {
            println!("{:#04X},", byte);
        } else {
            print!("{:#04X}, ", byte);
        }
    }
    Ok(())
}
