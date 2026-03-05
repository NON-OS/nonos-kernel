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
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use super::xhci::{XHCI_DB, XHCI_RT, XHCI_RT_ERDP, mw32, mw64, spin, TRB_CYCLE};


#[repr(C, align(4096))]
pub(crate) struct Ring256 { pub trbs: [[u32; 4]; 256] }

pub(crate) static mut CMD_RING: Ring256 = Ring256 { trbs: [[0; 4]; 256] };
pub(crate) static mut EVENT_RING: Ring256 = Ring256 { trbs: [[0; 4]; 256] };
pub(crate) static mut EP0_RING: Ring256 = Ring256 { trbs: [[0; 4]; 256] };
pub(crate) static mut HID_EP_RING: Ring256 = Ring256 { trbs: [[0; 4]; 256] };

pub(crate) static CMD_RING_IDX: AtomicU8 = AtomicU8::new(0);
pub(crate) static CMD_RING_CYC: AtomicBool = AtomicBool::new(true);
pub(crate) static EVT_RING_IDX: AtomicU8 = AtomicU8::new(0);
pub(crate) static EVT_RING_CYC: AtomicBool = AtomicBool::new(true);
pub(crate) static EP0_RING_IDX: AtomicU8 = AtomicU8::new(0);
pub(crate) static EP0_RING_CYC: AtomicBool = AtomicBool::new(true);
pub(crate) static HID_RING_IDX: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_RING_CYC: AtomicBool = AtomicBool::new(true);


pub fn queue_cmd(t0: u32, t1: u32, t2: u32, t3: u32) {
    let i = CMD_RING_IDX.load(Ordering::Relaxed) as usize;
    let c = CMD_RING_CYC.load(Ordering::Relaxed);
    unsafe {
        CMD_RING.trbs[i] = [t0, t1, t2, t3 | if c { TRB_CYCLE } else { 0 }];
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    let ni = (i + 1) % 255;
    if ni == 0 { CMD_RING_CYC.store(!c, Ordering::SeqCst); }
    CMD_RING_IDX.store(ni as u8, Ordering::SeqCst);

    let db = XHCI_DB.load(Ordering::Relaxed);
    if db != 0 { unsafe { mw32(db, 0); } }
}

pub fn queue_ep0(t0: u32, t1: u32, t2: u32, t3: u32) {
    let i = EP0_RING_IDX.load(Ordering::Relaxed) as usize;
    let c = EP0_RING_CYC.load(Ordering::Relaxed);
    unsafe {
        EP0_RING.trbs[i] = [t0, t1, t2, t3 | if c { TRB_CYCLE } else { 0 }];
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    let ni = (i + 1) % 255;
    if ni == 0 { EP0_RING_CYC.store(!c, Ordering::SeqCst); }
    EP0_RING_IDX.store(ni as u8, Ordering::SeqCst);
}

pub fn queue_hid(t0: u32, t1: u32, t2: u32, t3: u32) {
    let i = HID_RING_IDX.load(Ordering::Relaxed) as usize;
    let c = HID_RING_CYC.load(Ordering::Relaxed);
    unsafe {
        HID_EP_RING.trbs[i] = [t0, t1, t2, t3 | if c { TRB_CYCLE } else { 0 }];
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    let ni = (i + 1) % 255;
    if ni == 0 { HID_RING_CYC.store(!c, Ordering::SeqCst); }
    HID_RING_IDX.store(ni as u8, Ordering::SeqCst);
}

pub fn ring_db(slot: u8, ep: u8) {
    let db = XHCI_DB.load(Ordering::Relaxed);
    if db != 0 {
        unsafe { mw32(db + (slot as u64 * 4), ep as u32); }
    }
}

pub fn wait_event(timeout: u32) -> Option<(u8, u32, u32)> {
    let rt = XHCI_RT.load(Ordering::Relaxed);
    let ei = EVT_RING_IDX.load(Ordering::Relaxed) as usize;
    let ec = EVT_RING_CYC.load(Ordering::Relaxed);

    for _ in 0..timeout {
        // SAFETY: Hardware-synchronized event ring access, protected by cycle bit
        unsafe {
            let event_ring_ptr = addr_of_mut!(EVENT_RING);
            let t3 = core::ptr::read_volatile(&(*event_ring_ptr).trbs[ei][3]);
            if ((t3 & TRB_CYCLE) != 0) == ec {
                let t0 = (*event_ring_ptr).trbs[ei][0];
                let t2 = (*event_ring_ptr).trbs[ei][2];
                let trb_type = ((t3 >> 10) & 0x3F) as u8;
                let code = ((t3 >> 24) & 0xFF) as u32 | (t0 & 0xFFFF0000);

                let ni = (ei + 1) % 256;
                if ni == 0 { EVT_RING_CYC.store(!ec, Ordering::SeqCst); }
                EVT_RING_IDX.store(ni as u8, Ordering::SeqCst);

                let ep = event_ring_ptr as u64;
                mw64(rt + XHCI_RT_ERDP, ep + (ni as u64 * 16) | 0x08);

                return Some((trb_type, code, t2));
            }
        }
        spin(1);
    }
    None
}
