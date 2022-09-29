// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use lpc55_pac as device;

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
fn gpio_setup(
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
