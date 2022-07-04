use clap::Parser;
use dice::serial_certs::{CertType, Msg};
use pem::{EncodeConfig, LineEnding, Pem};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::{error, fmt, fs, io, io::Write, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    BufFull,
    CertGenFail,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BufFull => {
                write!(f, "Buffer provided is full before end of data.")
            }
            Error::CertGenFail => write!(f, "Cert generation failed."),
        }
    }
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum GetCertType {
    DeviceId,
    Alias,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0")]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600")]
    baud: u32,

    /// cert out file
    #[clap(long, default_value = "device-id.pem")]
    cert_out: String,

    /// cert type
    #[clap(long, value_enum, default_value = "device-id")]
    cert_type: GetCertType,
}

/// Get certificates from rot-r hubris task over uart.
/// Verify cert chain from alias cert to self-signed device-id:
/// $ cargo run --bin get-cert -- --cert-type device-id --cert-out device-id.pem
/// $ cargo run --bin get-cert -- --cert-type alias --cert-out alias.pem
/// $ openssl verify --CAfile device-id.pem --cert-out alias.pem
/// ./alias.pem: OK
fn main() -> Result<(), Box<dyn error::Error>> {
    let args = Args::parse();

    let cert_type = match args.cert_type {
        GetCertType::DeviceId => CertType::DeviceId,
        GetCertType::Alias => CertType::Alias,
    };

    println!("GetCertType: {:?}", cert_type);

    println!("device: {}, baud: {}", args.serial_dev, args.baud);
    let mut port = serialport::new(args.serial_dev.clone(), args.baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    let msg = Msg::CertPlz(cert_type);
    let mut data = [0u8; Msg::MAX_ENCODED_SIZE];
    println!("MAX_ENCODED_SIZE: {:#x}", Msg::MAX_ENCODED_SIZE);

    msg.encode(&mut data);
    send_msg(&mut port, &msg)?;
    println!("sent msg: {:?}", msg);

    let msg = recv_msg(&mut port)?;
    println!("recv'd response msg: {:?}", msg);

    let pem = match msg {
        // TODO: Cert needs to be a trait.
        Msg::DeviceIdCert(cert) => {
            if cert_type == CertType::DeviceId {
                der_to_pem(cert.as_bytes())
            } else {
                panic!("Got the wrong cert type!");
            }
        }
        Msg::Alias(cert) => {
            if cert_type == CertType::Alias {
                der_to_pem(cert.as_bytes())
            } else {
                panic!("Got the wrong cert type!");
            }
        }
        Msg::CertPlz(_) => panic!("invalid response"),
    };
    fs::write(args.cert_out, pem)?;

    Ok(())
}

fn send_msg(
    port: &mut Box<dyn SerialPort>,
    msg: &Msg,
) -> Result<(), io::Error> {
    // create buffer large enough to hold serialized Msg
    let mut buf = [0u8; Msg::MAX_ENCODED_SIZE];

    let size = msg.encode(&mut buf);

    // write to serial port
    port.write_all(&buf[..size])?;
    port.flush()
}

// replace with dice::mfg::decode_msg
fn recv_msg(port: &mut Box<dyn SerialPort>) -> Result<Msg, Error> {
    let mut encoded_buf = [0xFFu8; Msg::MAX_ENCODED_SIZE + 30];

    let size = read_all(port, &mut encoded_buf)?;

    // TODO: why do I get weird leading 0's when reading from serial port?
    println!("read_all: size: {:#x} -> {:?}", size, &encoded_buf[..size]);
    let start = encoded_buf.iter().position(|&x| x != 0).unwrap();

    Ok(Msg::from(&encoded_buf[start..]))
}

pub fn read_all(
    port: &mut Box<dyn SerialPort>,
    buf: &mut [u8],
) -> Result<usize, Error> {
    if buf.is_empty() {
        panic!("no zero sized buffers plz");
    }
    let mut pos = 0;
    let mut done = false;
    while !done {
        done = match port.read(&mut buf[pos..]) {
            Ok(bytes_read) => {
                pos += bytes_read;
                if buf[pos - 1] == 0 {
                    true
                } else {
                    if pos > buf.len() - 1 {
                        println!("buf.len(): {:#x}", buf.len());
                        println!("buf: {:?}", buf);
                        return Err(Error::BufFull);
                    }
                    false
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => false,
            Err(e) => panic!("read_all fail: {}", e),
        }
    }

    Ok(pos)
}

pub const PEM_CERT_TAG: &str = "CERTIFICATE";

pub fn der_to_pem(cert: &[u8]) -> String {
    let pem = Pem {
        tag: String::from(PEM_CERT_TAG),
        contents: cert.to_vec(),
    };
    pem::encode_config(
        &pem,
        EncodeConfig {
            line_ending: LineEnding::LF,
        },
    )
}
