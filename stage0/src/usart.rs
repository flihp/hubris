// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use lib_lpc55_usart::{Error, Read, Usart, Write};
use lpc55_pac as device;

/// Poll the usart reading all bytes into dst until a termination sequence
/// is encountered.
pub fn read_until(
    usart: &mut Usart,
    dst: &mut [u8],
    term: &[u8],
) -> Result<usize, Error> {
    if dst.is_empty() || term.is_empty() || term.len() > dst.len() {
        panic!("invalid dst or term");
    }
    let mut pos = 0;
    let mut done = false;
    while !done {
        done = match usart.read() {
            Ok(b) => {
                if pos > dst.len() - 1 {
                    return Err(Error::BufFull);
                }
                dst[pos] = b;
                pos += 1;
                // ensure we have at least as many bytes as the terminator
                if term.len() <= pos {
                    let mut done = true;
                    // not done till last term.len() bytes in dst are same
                    // as term
                    for (&b, &t) in
                        dst[..pos].iter().rev().zip(term.iter().rev())
                    {
                        if b != t {
                            done = false;
                        }
                    }
                    done
                } else {
                    false
                }
            }
            Err(nb::Error::WouldBlock) => false,
            Err(nb::Error::Other(e)) => return Err(e),
        }
    }
    Ok(pos)
}

/// Write all bytes in buf to usart fifo, poll if fifo is full.
/// NOTE: This does not guarantee transmission of all bytes. See flush_all.
pub fn write_all(usart: &mut Usart, src: &[u8]) -> Result<(), Error> {
    for b in src {
        let mut done = false;
        while !done {
            done = match usart.write(*b) {
                Ok(_) => true,
                Err(nb::Error::WouldBlock) => false,
                Err(nb::Error::Other(e)) => return Err(e),
            }
        }
    }
    Ok(())
}

/// Like 'flush' from embedded-hal 'Write' trait but polls till the transmit
/// FIFO is empty.
pub fn flush_all(usart: &mut Usart) {
    let mut done = false;
    while !done {
        done = match usart.flush() {
            Ok(_) => true,
            Err(nb::Error::WouldBlock) => false,
            Err(nb::Error::Other(_)) => false,
        }
    }
}

fn echo_till_str(usart: &mut Usart, term: &str, buf: &mut [u8]) -> bool {
    if term.len() > buf.len() {
        return false;
    }

    loop {
        match read_until(usart, buf, &[b'\r']) {
            Ok(size) => {
                if &buf[..size - 1] == term.as_bytes() {
                    return true;
                }
                match write_all(usart, &buf[..size]) {
                    Ok(_) => buf.fill(0),
                    Err(_) => (),
                }
            }
            Err(_) => match write_all(usart, "read error\n".as_bytes()) {
                Ok(_) => buf.fill(0),
                Err(_) => (),
            },
        }
    }
}

pub fn calibrate(usart: &mut Usart, buf: &mut [u8]) {
    let _ = write_all(usart, "echo_till_str: \"deviceid\"\n>".as_bytes());
    echo_till_str(usart, "deviceid", buf);
}

pub fn setup(
    syscon: &device::syscon::RegisterBlock,
    iocon: &device::iocon::RegisterBlock,
    flexcomm: &device::flexcomm0::RegisterBlock,
) {
    gpio_setup(syscon, iocon);
    flexcomm0_setup(syscon, flexcomm);
}

pub fn teardown(
    syscon: &device::syscon::RegisterBlock,
    iocon: &device::iocon::RegisterBlock,
    flexcomm: &device::flexcomm0::RegisterBlock,
) {
    gpio_teardown(syscon, iocon);
    flexcomm0_teardown(syscon, flexcomm);
}
/// Configure GPIO pin 29 & 30 for RX & TX respectively, as well as
/// digital mode.
pub fn gpio_setup(
    syscon: &device::syscon::RegisterBlock,
    iocon: &device::iocon::RegisterBlock,
) {
    // IOCON: enable clock & reset
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().enable());
    syscon.presetctrl0.modify(|_, w| w.iocon_rst().released());

    // GPIO: enable clock & reset
    syscon.ahbclkctrl0.modify(|_, w| w.gpio0().enable());
    syscon.presetctrl0.modify(|_, w| w.gpio0_rst().released());

    // configure GPIO pin 29 & 30 for RX & TX respectively, as well as
    // digital mode
    iocon
        .pio0_29
        .write(|w| w.func().alt1().digimode().digital());
    iocon
        .pio0_30
        .write(|w| w.func().alt1().digimode().digital());

    // disable IOCON clock
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().disable());
}

fn gpio_teardown(
    syscon: &device::syscon::RegisterBlock,
    iocon: &device::iocon::RegisterBlock,
) {
    // IOCON: enable clock & reset
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().enable());
    syscon.presetctrl0.modify(|_, w| w.iocon_rst().released());

    // reset pin 29 and 30 to defaults
    iocon.pio0_29.reset();
    iocon.pio0_30.reset();

    syscon.presetctrl0.modify(|_, w| w.iocon_rst().asserted());
    syscon.ahbclkctrl0.modify(|_, w| w.iocon().disable());

    syscon.presetctrl0.modify(|_, w| w.gpio0_rst().asserted());
    syscon.ahbclkctrl0.modify(|_, w| w.gpio0().disable());
}

fn flexcomm0_setup(
    syscon: &device::syscon::RegisterBlock,
    flexcomm: &device::flexcomm0::RegisterBlock,
) {
    syscon.ahbclkctrl1.modify(|_, w| w.fc0().enable());
    syscon.presetctrl1.modify(|_, w| w.fc0_rst().released());

    // Set flexcom to be a USART
    flexcomm.pselid.write(|w| w.persel().usart());

    // set flexcomm0 / uart clock to 12Mhz
    syscon.fcclksel0().modify(|_, w| w.sel().enum_0x2());
}

fn flexcomm0_teardown(
    syscon: &device::syscon::RegisterBlock,
    flexcomm: &device::flexcomm0::RegisterBlock,
) {
    // set flexcomm0 clock to default (no clock)
    syscon.fcclksel0().modify(|_, w| w.sel().enum_0x7());

    // set flexcomm0 peripheral select to default
    flexcomm.pselid.write(|w| w.persel().no_periph_selected());

    syscon.presetctrl1.modify(|_, w| w.fc0_rst().asserted());
    syscon.ahbclkctrl1.modify(|_, w| w.fc0().disable());
}
