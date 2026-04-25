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

//! xHCI TRB ring management

use super::xhci::{coop_tick, mw32, mw64, TRB_CYCLE, XHCI_DB, XHCI_RT, XHCI_RT_ERDP};
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

// xHCI Link TRB (type 6) — placed at ring slot 255 so the controller wraps back
// to slot 0 instead of stalling on a zero-filled entry.
const TRB_TYPE_LINK: u32 = 6;
const TRB_TC: u32 = 1 << 1; // Toggle Cycle bit

// =============================================================================
// Ring Structures
// =============================================================================

#[repr(C, align(4096))]
pub(crate) struct Ring256 {
    pub trbs: [[u32; 4]; 256],
}

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

// =============================================================================
// Ring Operations
// =============================================================================

pub fn queue_cmd(t0: u32, t1: u32, t2: u32, t3: u32) {
    let i = CMD_RING_IDX.load(Ordering::Relaxed) as usize;
    let c = CMD_RING_CYC.load(Ordering::Relaxed);
    unsafe {
        CMD_RING.trbs[i] = [t0, t1, t2, t3 | if c { TRB_CYCLE } else { 0 }];
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    let ni = (i + 1) % 255;
    if ni == 0 {
        CMD_RING_CYC.store(!c, Ordering::SeqCst);
    }
    CMD_RING_IDX.store(ni as u8, Ordering::SeqCst);

    // Ring doorbell 0
    let db = XHCI_DB.load(Ordering::Relaxed);
    if db != 0 {
        unsafe {
            mw32(db, 0);
        }
    }
}

pub fn queue_ep0(t0: u32, t1: u32, t2: u32, t3: u32) {
    let i = EP0_RING_IDX.load(Ordering::Relaxed) as usize;
    let c = EP0_RING_CYC.load(Ordering::Relaxed);
    unsafe {
        EP0_RING.trbs[i] = [t0, t1, t2, t3 | if c { TRB_CYCLE } else { 0 }];
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    let ni = (i + 1) % 255;
    if ni == 0 {
        EP0_RING_CYC.store(!c, Ordering::SeqCst);
    }
    EP0_RING_IDX.store(ni as u8, Ordering::SeqCst);
}

pub fn queue_hid(t0: u32, t1: u32, t2: u32, t3: u32) {
    let i = HID_RING_IDX.load(Ordering::Relaxed) as usize;
    let c = HID_RING_CYC.load(Ordering::Relaxed);
    // SAFETY: Single-threaded access; volatile writes required because the
    // xHCI controller reads these TRBs via DMA.
    unsafe {
        let trb = &mut HID_EP_RING.trbs[i];
        core::ptr::write_volatile(&mut trb[0], t0);
        core::ptr::write_volatile(&mut trb[1], t1);
        core::ptr::write_volatile(&mut trb[2], t2);
        core::ptr::write_volatile(&mut trb[3], t3 | if c { TRB_CYCLE } else { 0 });
        core::sync::atomic::fence(Ordering::SeqCst);
    }
    let ni = (i + 1) % 255;
    if ni == 0 {
        // Ring is wrapping: write (or refresh) the Link TRB at slot 255.
        //
        // The Link TRB must carry the CURRENT lap's cycle bit (`c`) so the
        // xHCI controller recognises it as valid after consuming TRB[254].
        // TRB_TC=1 causes the controller to toggle its consumer cycle bit
        // when it processes the Link TRB, so it matches the next lap.
        //
        // This write happens inside queue_hid(), which is called from
        // start_hid_poll() BEFORE ring_db() — so the Link TRB is always
        // ready before the controller is signalled to advance past TRB[254].
        //
        // SAFETY: slot 255 is reserved exclusively for the Link TRB;
        // volatile writes needed because xHCI DMA reads this memory.
        unsafe {
            let ring_p = addr_of_mut!(HID_EP_RING) as u64;
            let link = &mut HID_EP_RING.trbs[255];
            core::ptr::write_volatile(&mut link[0], (ring_p & 0xFFFF_FFFF) as u32);
            core::ptr::write_volatile(&mut link[1], (ring_p >> 32) as u32);
            core::ptr::write_volatile(&mut link[2], 0);
            core::ptr::write_volatile(
                &mut link[3],
                (TRB_TYPE_LINK << 10) | TRB_TC | if c { TRB_CYCLE } else { 0 },
            );
            core::sync::atomic::fence(Ordering::SeqCst);
        }
        HID_RING_CYC.store(!c, Ordering::SeqCst);
    }
    HID_RING_IDX.store(ni as u8, Ordering::SeqCst);
}

pub fn ring_db(slot: u8, ep: u8) {
    let db = XHCI_DB.load(Ordering::Relaxed);
    if db != 0 {
        unsafe {
            mw32(db + (slot as u64 * 4), ep as u32);
        }
    }
}

pub fn wait_event(timeout: u32) -> Option<(u8, u32, u32)> {
    let rt = XHCI_RT.load(Ordering::Relaxed);

    for i in 0..timeout {
        let ei = EVT_RING_IDX.load(Ordering::Relaxed) as usize;
        let ec = EVT_RING_CYC.load(Ordering::Relaxed);
        // SAFETY: Hardware-synchronized event ring access, protected by cycle bit
        unsafe {
            let event_ring_ptr = addr_of_mut!(EVENT_RING);
            let t3 = core::ptr::read_volatile(&(*event_ring_ptr).trbs[ei][3]);
            if ((t3 & TRB_CYCLE) != 0) == ec {
                let t2 = core::ptr::read_volatile(&(*event_ring_ptr).trbs[ei][2]);
                let trb_type = ((t3 >> 10) & 0x3F) as u8;
                let cc = (t2 >> 24) & 0xFF;

                let ni = (ei + 1) % 256;
                if ni == 0 {
                    EVT_RING_CYC.store(!ec, Ordering::SeqCst);
                }
                EVT_RING_IDX.store(ni as u8, Ordering::SeqCst);

                let ep = event_ring_ptr as u64;
                mw64(rt + XHCI_RT_ERDP, ep + (ni as u64 * 16) | 0x08);

                return Some((trb_type, cc, t3));
            }
        }
        coop_tick(i);
    }
    None
}

/// Non-blocking event check — returns immediately if no event is ready.
pub fn check_event() -> Option<(u8, u32, u32)> {
    let rt = XHCI_RT.load(Ordering::Relaxed);
    let ei = EVT_RING_IDX.load(Ordering::Relaxed) as usize;
    let ec = EVT_RING_CYC.load(Ordering::Relaxed);

    // SAFETY: Hardware-synchronized event ring access, protected by cycle bit
    unsafe {
        let event_ring_ptr = addr_of_mut!(EVENT_RING);
        let t3 = core::ptr::read_volatile(&(*event_ring_ptr).trbs[ei][3]);
        if ((t3 & TRB_CYCLE) != 0) == ec {
            let t2 = core::ptr::read_volatile(&(*event_ring_ptr).trbs[ei][2]);
            let trb_type = ((t3 >> 10) & 0x3F) as u8;
            let cc = (t2 >> 24) & 0xFF;

            let ni = (ei + 1) % 256;
            if ni == 0 {
                EVT_RING_CYC.store(!ec, Ordering::SeqCst);
            }
            EVT_RING_IDX.store(ni as u8, Ordering::SeqCst);

            let ep = event_ring_ptr as u64;
            mw64(rt + XHCI_RT_ERDP, ep + (ni as u64 * 16) | 0x08);

            return Some((trb_type, cc, t3));
        }
    }
    None
}
