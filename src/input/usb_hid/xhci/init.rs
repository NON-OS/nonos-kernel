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

use core::ptr::addr_of_mut;
use core::sync::atomic::Ordering;
use crate::sys::serial;
use super::consts::*;
use super::structures::{DCBAA, ERST, SCRATCHPAD_ARRAY, SCRATCHPAD_PAGES};
use super::state::{XHCI_BAR, XHCI_OP, XHCI_DB, XHCI_RT, MAX_PORTS};
use super::low_level::{mr32, mw32, mw64, spin, coop_tick};
use super::ports::scan_ports;
use crate::input::usb_hid::ring::{CMD_RING, EVENT_RING};

pub fn init_xhci(bar: u64) -> bool {
    serial::println(b"[USB] Init xHCI...");
    unsafe {
        let cap = mr32(bar + XHCI_CAP_CAPLENGTH);
        let cap_len = (cap & 0xFF) as u64;
        let op = bar + cap_len;
        let db_off = mr32(bar + XHCI_CAP_DBOFF) & 0xFFFFFFFC;
        let rt_off = mr32(bar + XHCI_CAP_RTSOFF) & 0xFFFFFFE0;
        let db = bar + db_off as u64;
        let rt = bar + rt_off as u64;
        let hcs1 = mr32(bar + XHCI_CAP_HCSPARAMS1);
        let max_slots = (hcs1 & 0xFF) as u8;
        let max_ports = ((hcs1 >> 24) & 0xFF) as u8;

        let hcs2 = mr32(bar + XHCI_CAP_HCSPARAMS2);
        let sp_hi = (hcs2 >> 21) & 0x1F;
        let sp_lo = (hcs2 >> 27) & 0x1F;
        let max_sp = (sp_hi << 5) | sp_lo;

        serial::print(b"[USB] Ports ");
        serial::print_dec(max_ports as u64);
        serial::print(b" Slots ");
        serial::print_dec(max_slots as u64);
        serial::print(b" SP ");
        serial::print_dec(max_sp as u64);
        serial::println(b"");

        XHCI_BAR.store(bar, Ordering::SeqCst);
        XHCI_OP.store(op, Ordering::SeqCst);
        XHCI_DB.store(db, Ordering::SeqCst);
        XHCI_RT.store(rt, Ordering::SeqCst);
        MAX_PORTS.store(max_ports, Ordering::SeqCst);
        if !stop_and_reset(op) { return false; }
        setup_structures(op, rt, max_slots, max_sp);

        // Start controller
        mw32(op + XHCI_OP_USBCMD, USBCMD_RS | USBCMD_INTE);
        spin(10000);
        let sts = mr32(op + XHCI_OP_USBSTS);
        if (sts & USBSTS_HCH) != 0 {
            serial::println(b"[USB] Start fail");
            return false;
        }
        if (sts & (1 << 2)) != 0 {
            serial::println(b"[USB] HSE!");
        }
        if (sts & (1 << 12)) != 0 {
            serial::println(b"[USB] HCE!");
        }
        serial::println(b"[USB] xHCI running");
        scan_ports(op, max_ports);
    }
    true
}

unsafe fn stop_and_reset(op: u64) -> bool {
    if (mr32(op + XHCI_OP_USBCMD) & USBCMD_RS) != 0 {
        mw32(op + XHCI_OP_USBCMD, mr32(op + XHCI_OP_USBCMD) & !USBCMD_RS);
        for i in 0..100_000u32 {
            if (mr32(op + XHCI_OP_USBSTS) & USBSTS_HCH) != 0 { break; }
            coop_tick(i);
        }
    }
    mw32(op + XHCI_OP_USBCMD, USBCMD_HCRST);
    for i in 0..1_000_000u32 {
        if (mr32(op + XHCI_OP_USBCMD) & USBCMD_HCRST) == 0
           && (mr32(op + XHCI_OP_USBSTS) & USBSTS_CNR) == 0 { break; }
        coop_tick(i);
    }
    if (mr32(op + XHCI_OP_USBSTS) & USBSTS_CNR) != 0 {
        serial::println(b"[USB] Reset fail");
        return false;
    }
    true
}

unsafe fn setup_structures(op: u64, rt: u64, max_slots: u8, max_sp: u32) {
    // Configure max slots
    mw32(op + XHCI_OP_CONFIG, max_slots.min(16) as u32);

    // DCBAA
    let dcbaa_p = addr_of_mut!(DCBAA) as u64;
    mw64(op + XHCI_OP_DCBAAP, dcbaa_p);

    // Scratchpad buffers (required by some controllers)
    if max_sp > 0 {
        let sp_count = max_sp.min(16) as usize;
        let sp_array_p = addr_of_mut!(SCRATCHPAD_ARRAY) as u64;
        for i in 0..sp_count {
            let page_p = addr_of_mut!(SCRATCHPAD_PAGES[i]) as u64;
            SCRATCHPAD_ARRAY.entries[i] = page_p;
        }
        DCBAA.entries[0] = sp_array_p;
        serial::print(b"[USB] SP array=0x");
        serial::print_hex(sp_array_p);
        serial::println(b"");
    }

    // Command ring
    let cmd_p = addr_of_mut!(CMD_RING) as u64;
    mw64(op + XHCI_OP_CRCR, cmd_p | 1);

    // Event ring - MUST init in order: ERSTSZ -> ERDP -> ERSTBA
    let evt_p = addr_of_mut!(EVENT_RING) as u64;
    let erst_ptr = addr_of_mut!(ERST);
    (*erst_ptr).ring_base = evt_p;
    (*erst_ptr).ring_size = 256;
    let erst_p = erst_ptr as u64;

    mw32(rt + XHCI_RT_ERSTSZ, 1);
    mw64(rt + XHCI_RT_ERDP, evt_p);
    mw64(rt + XHCI_RT_ERSTBA, erst_p);

    serial::print(b"[USB] DCBAA=0x");
    serial::print_hex(dcbaa_p);
    serial::print(b" CMD=0x");
    serial::print_hex(cmd_p);
    serial::print(b" EVT=0x");
    serial::print_hex(evt_p);
    serial::println(b"");
}
