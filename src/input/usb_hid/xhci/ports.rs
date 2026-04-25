// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::consts::*;
use super::enumerate::enumerate_device;
use super::low_level::{coop_tick, mr32, mw32, spin};
use super::state::{DEV_SPEED, PORT_ID};
use crate::input::usb_hid::USB_INIT;
use crate::sys::serial;
use core::sync::atomic::Ordering;

pub(super) fn scan_ports(op: u64, max_ports: u8) {
    for port in 1..=max_ports {
        let pa = op + XHCI_OP_PORTSC_BASE + ((port as u64 - 1) * 0x10);
        unsafe {
            let ps = mr32(pa);
            if (ps & PORTSC_CCS) != 0 {
                serial::print(b"[USB] Port ");
                serial::print_dec(port as u64);
                let spd = (ps >> 10) & 0xF;
                serial::print(b" spd ");
                serial::print_dec(spd as u64);
                serial::println(b"");
                if (ps & PORTSC_PP) == 0 {
                    mw32(pa, ps | PORTSC_PP);
                    spin(100_000);
                }
                let ps2 = mr32(pa);
                mw32(
                    pa,
                    (ps2 & !PORTSC_PLS_MASK) | PORTSC_PR | PORTSC_CSC | PORTSC_PRC | PORTSC_WRC,
                );
                for i in 0..500_000u32 {
                    let s = mr32(pa);
                    if (s & PORTSC_PRC) != 0 {
                        mw32(pa, s | PORTSC_PRC);
                        if (s & PORTSC_PED) != 0 {
                            serial::println(b"[USB] Port enabled");
                            PORT_ID.store(port, Ordering::SeqCst);
                            DEV_SPEED.store(((s >> 10) & 0xF) as u8, Ordering::SeqCst);
                            if enumerate_device(port, ((s >> 10) & 0xF) as u8) {
                                USB_INIT.store(true, Ordering::SeqCst);
                                return;
                            }
                        }
                        break;
                    }
                    coop_tick(i);
                }
            }
        }
    }
}
