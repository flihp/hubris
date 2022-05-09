use clap::Parser;
use dice::{
    cert::Cert,
    csr::Csr,
    mfg::{Msg, Msgs},
};
use pem::{EncodeConfig, Pem};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::{
    env, fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0")]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600")]
    baud: u32,

    /// CSR out file
    #[clap(long, default_value = "csr.pem")]
    csr_out: String,

    /// directory hosting CA
    #[clap(long)]
    ca_dir: Option<PathBuf>,

    /// OpenSSL config file
    #[clap(long, default_value = "openssl.cnf")]
    openssl_conf: String,

    /// cert out file
    #[clap(long, default_value = "cert.pem")]
    cert_out: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    BadTag,
    BufFull,
    CertGenFail,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadTag => write!(f, "PEM file has wrong tag value."),
            Error::BufFull => {
                write!(f, "Buffer provided is full before end of data.")
            }
            Error::CertGenFail => write!(f, "Cert generation failed."),
        }
    }
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
                        println!("buf.len(): {}", buf.len());
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
    let mut encoded_buf = [0xFFu8; Msg::MAX_ENCODED_SIZE];

    let size = read_all(port, &mut encoded_buf)?;

    // TODO: why do I get weird leading 0's when reading from serial port?
    println!("read_all: size: {:#x} -> {:?}", size, &encoded_buf[..size]);
    let start = encoded_buf.iter().position(|&x| x != 0).unwrap();

    Ok(Msg::from(&encoded_buf[start..]))
}

fn csr_to_cert(
    csr: &Csr,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("writing buf to file at: {}", args.csr_out);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&args.csr_out)?;

    let csr_pem = pem::encode_config(
        &Pem {
            tag: String::from("CERTIFICATE REQUEST"),
            contents: csr.as_bytes().to_vec(),
        },
        EncodeConfig {
            line_ending: pem::LineEnding::LF,
        },
    );
    f.write_all(csr_pem.as_bytes())?;

    let ca_dir = args
        .ca_dir
        .clone()
        .unwrap_or_else(|| env::current_dir().expect("no PWD?"));
    println!("openssl pwd: {}", ca_dir.display());

    // generate / sign cert
    let mut cmd = Command::new("openssl");
    println!("ca_dir: {}", ca_dir.display());
    cmd.current_dir(ca_dir)
        .arg("ca")
        .arg("-config")
        .arg(&args.openssl_conf)
        .arg("-name")
        .arg("ca_deviceid")
        .arg("-extensions")
        .arg("v3_deviceid")
        .arg("-days")
        // DICE spec wants us to use 99991231235959Z as the expiration
        // to indicate it won't expire but openssl commands only take days
        // from current so 24000 is the best we can do with 'openssl ca'.
        // UPDATE:
        // FALSE! -days is one way to do it, but you can provide -enddate
        //   '99991231235959Z'. This applies to -startdate too.
        .arg("24000")
        .arg("-notext")
        .arg("-md")
        .arg("sha3-256")
        .arg("-in")
        .arg(&args.csr_out)
        .arg("-out")
        .arg(&args.cert_out);

    println!("command: {:?}", cmd);

    let status = cmd.status()?;
    if status.success() {
        println!("done with status: {}", status);
        Ok(())
    } else {
        Err(Box::new(Error::CertGenFail))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("device: {}, baud: {}", args.serial_dev, args.baud);
    let mut port = serialport::new(args.serial_dev.clone(), args.baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    // send message requesting CSR from RoT
    // create message struct
    let msg = Msg {
        id: 666,
        msg: Msgs::CsrPlz,
    };
    send_msg(&mut port, &msg)?;

    // turn this dial if we start getting leading 0's
    thread::sleep(Duration::from_millis(170));

    // receive message
    // deserialize into Msg struct
    let resp = recv_msg(&mut port)?;

    if let Msgs::Csr(buf) = resp.msg {
        csr_to_cert(&buf, &args)?;
    } else {
        panic!("Expecting CSR msg, got {:?}", resp);
    }

    let cert = fs::read_to_string(&args.cert_out)?;
    let cert = pem::parse(cert)?;
    if cert.tag != "CERTIFICATE" {
        return Err(Box::new(Error::BadTag));
    }

    println!("cert.contents.len(): {}", cert.contents.len());
    let cert = Cert::from(&cert.contents.try_into().unwrap());
    let msg = Msg {
        id: 668,
        msg: Msgs::Cert(cert),
    };
    send_msg(&mut port, &msg)?;

    Ok(())
}
