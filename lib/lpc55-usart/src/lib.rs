// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![no_std]

pub use embedded_hal::serial::{Read, Write};
use lpc55_pac as device;
use unwrap_lite::UnwrapLite;

cfg_if::cfg_if! {
    // if we're talking to tasks get their TaskIds & configuration data
    if #[cfg(feature = "tasks")] {
        use userlib::task_slot;
        use drv_lpc55_syscon_api::{Peripheral, Syscon};

        task_slot!(SYSCON, syscon_driver);
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Error {
    Frame,
    Parity,
    Noise,
    BufFull,
}

pub struct Usart<'a> {
    usart: &'a device::usart0::RegisterBlock,
}

impl Write<u8> for Usart<'_> {
    type Error = Error;

    fn flush(&mut self) -> nb::Result<(), Error> {
        if self.is_tx_idle() {
            Ok(())
        } else {
            Err(nb::Error::WouldBlock)
        }
    }

    fn write(&mut self, byte: u8) -> nb::Result<(), Error> {
        if !self.is_tx_full() {
            // This is unsafe because we can transmit 7, 8 or 9 bytes but the
            // interface can't know what it's been configured for?
            self.usart.fifowr.write(|w| unsafe { w.bits(byte as u32) });
            Ok(())
        } else {
            Err(nb::Error::WouldBlock)
        }
    }
}

impl Read<u8> for Usart<'_> {
    type Error = Error;

    fn read(&mut self) -> nb::Result<u8, Self::Error> {
        if !self.is_rx_empty() {
            let byte = self.usart.fiford.read().rxdata().bits();
            // TODO: errors became a problem, so I disabled them and then
            // everything just started working again?
            if self.is_rx_frame_err() {
                Err(nb::Error::Other(Error::Frame))
            } else if self.is_rx_parity_err() {
                Err(nb::Error::Other(Error::Parity))
            } else if self.is_rx_noise_err() {
                Err(nb::Error::Other(Error::Noise))
            } else {
                // assume 8 bit data
                Ok(byte.try_into().unwrap_lite())
            }
        } else {
            Err(nb::Error::WouldBlock)
        }
    }
}

impl<'a> Usart<'a> {
    #[cfg(feature = "tasks")]
    pub fn turn_on(
        flexcomm: &device::flexcomm0::RegisterBlock,
        usart: &'a device::usart0::RegisterBlock,
    ) -> Self {
        let syscon = Syscon::from(SYSCON.get_task_id());

        syscon.enable_clock(Peripheral::Fc0).unwrap_lite();
        syscon.leave_reset(Peripheral::Fc0).unwrap_lite();

        Usart::turn_on_common(flexcomm, usart)
    }

    #[cfg(not(feature = "tasks"))]
    pub fn turn_on(
        syscon: &device::syscon::RegisterBlock,
        iocon: &device::iocon::RegisterBlock,
        flexcomm: &device::flexcomm0::RegisterBlock,
        usart: &'a device::usart0::RegisterBlock,
    ) -> Self {
        // IOCON: enable clock & reset
        syscon.ahbclkctrl0.modify(|_, w| w.iocon().enable());
        syscon.presetctrl0.modify(|_, w| w.iocon_rst().released());

        // GPIO: enable clock & reset
        // this should work but doesn't ... pac crate bug?
        //syscon.ahbclkctrl0.write(|w| w.gpio0().enable());
        // this is what drv-lpc55-syscon does (it works)
        syscon
            .ahbclkctrl0
            .modify(|r, w| unsafe { w.bits(r.bits() | 0x4000) });
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

        // set flexcomm0 / uart clock to 12Mhz
        syscon.fcclksel0().modify(|_, w| w.sel().enum_0x2());

        // flexcom0: enable clock & reset
        syscon.ahbclkctrl1.modify(|_, w| w.fc0().enable());
        syscon.presetctrl1.modify(|_, w| w.fc0_rst().released());

        Usart::turn_on_common(flexcomm, usart)
    }

    #[cfg(not(feature = "tasks"))]
    pub fn turn_off(
        syscon: &device::syscon::RegisterBlock,
        _iocon: &device::iocon::RegisterBlock,
        _flexcomm: &device::flexcomm0::RegisterBlock,
    ) {
        syscon.presetctrl0.modify(|_, w| w.iocon_rst().asserted());
        syscon.ahbclkctrl0.modify(|_, w| w.iocon().disable());

        syscon.presetctrl0.modify(|_, w| w.gpio0_rst().asserted());
        syscon.ahbclkctrl0.modify(|_, w| w.gpio0().disable());

        syscon.presetctrl1.modify(|_, w| w.fc0_rst().asserted());
        syscon.ahbclkctrl1.modify(|_, w| w.fc0().disable());
    }

    fn turn_on_common(
        flexcomm: &device::flexcomm0::RegisterBlock,
        usart: &'a device::usart0::RegisterBlock,
    ) -> Self {
        // Set flexcom to be a USART
        flexcomm.pselid.write(|w| w.persel().usart());

        // enable transmit & receive
        usart
            .fifocfg
            .modify(|_, w| w.enabletx().enabled().enablerx().enabled());

        // This puts us at 9600 baud because it divides nicely with the
        // 12mhz clock
        usart.brg.write(|w| unsafe { w.brgval().bits(0x7c) });
        usart.osr.write(|w| unsafe { w.osrval().bits(0x9) });

        // 8N1 configuration
        usart.cfg.write(|w| unsafe {
            w.paritysel()
                .bits(0)
                .stoplen()
                .bit(false)
                .datalen()
                .bits(1)
                .loop_()
                .normal()
                .syncen()
                .asynchronous_mode()
                .clkpol()
                .falling_edge()
                .enable()
                .enabled()
        });

        Usart { usart }
    }

    // write all bytes in buf, block / spin if fifo is full
    // NOTE: this does not block till all bytes have been transmitted,
    // see flush_all.
    pub fn write_all(&mut self, src: &[u8]) -> Result<(), Error> {
        for b in src {
            let mut done = false;
            while !done {
                done = match self.write(*b) {
                    Ok(_) => true,
                    Err(nb::Error::WouldBlock) => false,
                    Err(nb::Error::Other(e)) => return Err(e),
                }
            }
        }
        Ok(())
    }

    // Poll the usart reading all bytes till a termination sequence is
    // encountered.
    pub fn read_until(
        &mut self,
        dst: &mut [u8],
        term: &[u8],
    ) -> Result<usize, Error> {
        if dst.is_empty() || term.is_empty() || term.len() > dst.len() {
            panic!("invalid dst or term");
        }
        let mut pos = 0;
        let mut done = false;
        while !done {
            done = match self.read() {
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

    // Like 'flush' from embedded-hal Write trait but blocks till the transmit
    // FIFO is empty.
    pub fn flush_all(&mut self) {
        let mut done = false;
        while !done {
            done = match self.flush() {
                Ok(_) => true,
                Err(nb::Error::WouldBlock) => false,
                Err(nb::Error::Other(_)) => false,
            }
        }
    }

    pub fn is_tx_full(&self) -> bool {
        !self.usart.fifostat.read().txnotfull().bit()
    }

    pub fn is_rx_empty(&self) -> bool {
        !self.usart.fifostat.read().rxnotempty().bit()
    }

    pub fn is_rx_frame_err(&self) -> bool {
        self.usart.fiford.read().framerr().bit()
    }

    pub fn is_rx_parity_err(&self) -> bool {
        self.usart.fiford.read().parityerr().bit()
    }

    pub fn is_rx_noise_err(&self) -> bool {
        self.usart.fiford.read().rxnoise().bit()
    }

    pub fn is_tx_idle(&self) -> bool {
        self.usart.stat.read().txidle().bit()
    }

    pub fn set_tx_idle_interrupt(&self) {
        self.usart.intenset.modify(|_, w| w.txidleen().set_bit());
    }

    pub fn clear_tx_idle_interrupt(&self) {
        self.usart.intenclr.write(|w| w.txidleclr().set_bit());
    }
}
