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
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use crate::sys::serial;
use super::ring::{CMD_RING, EVENT_RING, EP0_RING, HID_EP_RING, EVT_RING_IDX, queue_cmd, wait_event};
use super::transfer::{get_descriptor, set_configuration, set_protocol, set_idle, parse_config_descriptor};
use super::hid::start_hid_poll;
use super::{USB_INIT, KBD_AVAIL, MOUSE_AVAIL};


pub(crate) const XHCI_CAP_CAPLENGTH: u64 = 0x00;
pub(crate) const XHCI_CAP_HCSPARAMS1: u64 = 0x04;
pub(crate) const XHCI_CAP_DBOFF: u64 = 0x14;
pub(crate) const XHCI_CAP_RTSOFF: u64 = 0x18;

pub(crate) const XHCI_OP_USBCMD: u64 = 0x00;
pub(crate) const XHCI_OP_USBSTS: u64 = 0x04;
pub(crate) const XHCI_OP_CRCR: u64 = 0x18;
pub(crate) const XHCI_OP_DCBAAP: u64 = 0x30;
pub(crate) const XHCI_OP_CONFIG: u64 = 0x38;
pub(crate) const XHCI_OP_PORTSC_BASE: u64 = 0x400;

pub(crate) const XHCI_RT_ERSTSZ: u64 = 0x28;
pub(crate) const XHCI_RT_ERSTBA: u64 = 0x30;
pub(crate) const XHCI_RT_ERDP: u64 = 0x38;

pub(crate) const USBCMD_RS: u32 = 1 << 0;
pub(crate) const USBCMD_HCRST: u32 = 1 << 1;
pub(crate) const USBCMD_INTE: u32 = 1 << 2;

pub(crate) const USBSTS_HCH: u32 = 1 << 0;
pub(crate) const USBSTS_CNR: u32 = 1 << 11;

pub(crate) const PORTSC_CCS: u32 = 1 << 0;
pub(crate) const PORTSC_PED: u32 = 1 << 1;
pub(crate) const PORTSC_PR: u32 = 1 << 4;
pub(crate) const PORTSC_PLS_MASK: u32 = 0xF << 5;
pub(crate) const PORTSC_PP: u32 = 1 << 9;
pub(crate) const PORTSC_CSC: u32 = 1 << 17;
pub(crate) const PORTSC_PRC: u32 = 1 << 21;
pub(crate) const PORTSC_WRC: u32 = 1 << 19;


pub(crate) const TRB_TYPE_ENABLE_SLOT: u32 = 9;
pub(crate) const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
pub(crate) const TRB_TYPE_CONFIGURE_ENDPOINT: u32 = 12;

pub(crate) const TRB_CYCLE: u32 = 1 << 0;


#[repr(C, align(4096))]
pub(crate) struct DcbaaArray { pub entries: [u64; 17] }
pub(crate) static mut DCBAA: DcbaaArray = DcbaaArray { entries: [0; 17] };

#[repr(C, align(64))]
pub(crate) struct EventRingSegmentTable {
    pub ring_base: u64,
    pub ring_size: u16,
    pub _rsvd: [u16; 3],
}
pub(crate) static mut ERST: EventRingSegmentTable = EventRingSegmentTable {
    ring_base: 0, ring_size: 256, _rsvd: [0; 3],
};

#[repr(C, align(4096))]
pub(crate) struct DeviceContext {
    pub slot: [u32; 8],
    pub ep: [[u32; 8]; 31],
}
pub(crate) static mut DEV_CTX: DeviceContext = DeviceContext { slot: [0; 8], ep: [[0; 8]; 31] };

#[repr(C, align(4096))]
pub(crate) struct InputContext {
    pub ctrl: [u32; 8],
    pub slot: [u32; 8],
    pub ep: [[u32; 8]; 31],
}
pub(crate) static mut INPUT_CTX: InputContext = InputContext {
    ctrl: [0; 8], slot: [0; 8], ep: [[0; 8]; 31],
};

#[repr(C, align(4096))]
pub(crate) struct UsbBuffer { pub data: [u8; 4096] }
pub(crate) static mut USB_BUF: UsbBuffer = UsbBuffer { data: [0; 4096] };


pub(crate) static XHCI_BAR: AtomicU64 = AtomicU64::new(0);
pub(crate) static XHCI_OP: AtomicU64 = AtomicU64::new(0);
pub(crate) static XHCI_DB: AtomicU64 = AtomicU64::new(0);
pub(crate) static XHCI_RT: AtomicU64 = AtomicU64::new(0);
pub(crate) static MAX_PORTS: AtomicU8 = AtomicU8::new(0);

pub(crate) static SLOT_ID: AtomicU8 = AtomicU8::new(0);
pub(crate) static DEV_SPEED: AtomicU8 = AtomicU8::new(0);
pub(crate) static PORT_ID: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_EP_ADDR: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_EP_DCI: AtomicU8 = AtomicU8::new(0);
pub(crate) static HID_INTERVAL: AtomicU8 = AtomicU8::new(8);
pub(crate) static MAX_PACKET: AtomicU8 = AtomicU8::new(8);


#[inline]
pub(crate) unsafe fn mr32(a: u64) -> u32 { unsafe { core::ptr::read_volatile(a as *const u32) } }
#[inline]
pub(crate) unsafe fn mw32(a: u64, v: u32) { unsafe { core::ptr::write_volatile(a as *mut u32, v); } }
#[inline]
pub(crate) unsafe fn mw64(a: u64, v: u64) { unsafe { core::ptr::write_volatile(a as *mut u64, v); } }

pub(crate) fn spin(n: u32) { for _ in 0..n { core::hint::spin_loop(); } }


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

        serial::print(b"[USB] Ports ");
        serial::print_dec(max_ports as u64);
        serial::println(b"");

        XHCI_BAR.store(bar, Ordering::SeqCst);
        XHCI_OP.store(op, Ordering::SeqCst);
        XHCI_DB.store(db, Ordering::SeqCst);
        XHCI_RT.store(rt, Ordering::SeqCst);
        MAX_PORTS.store(max_ports, Ordering::SeqCst);

        if (mr32(op + XHCI_OP_USBCMD) & USBCMD_RS) != 0 {
            mw32(op + XHCI_OP_USBCMD, mr32(op + XHCI_OP_USBCMD) & !USBCMD_RS);
            for _ in 0..100_000 {
                if (mr32(op + XHCI_OP_USBSTS) & USBSTS_HCH) != 0 { break; }
                spin(1);
            }
        }

        mw32(op + XHCI_OP_USBCMD, USBCMD_HCRST);
        for _ in 0..1_000_000 {
            if (mr32(op + XHCI_OP_USBCMD) & USBCMD_HCRST) == 0
               && (mr32(op + XHCI_OP_USBSTS) & USBSTS_CNR) == 0 { break; }
            spin(1);
        }
        if (mr32(op + XHCI_OP_USBSTS) & USBSTS_CNR) != 0 {
            serial::println(b"[USB] Reset fail");
            return false;
        }

        let dcbaa_p = addr_of_mut!(DCBAA) as u64;
        mw64(op + XHCI_OP_DCBAAP, dcbaa_p);

        let cmd_p = addr_of_mut!(CMD_RING) as u64;
        mw64(op + XHCI_OP_CRCR, cmd_p | 1);

        let evt_p = addr_of_mut!(EVENT_RING) as u64;
        let erst_ptr = addr_of_mut!(ERST);
        (*erst_ptr).ring_base = evt_p;
        (*erst_ptr).ring_size = 256;
        let erst_p = erst_ptr as u64;

        mw32(rt + XHCI_RT_ERSTSZ, 1);
        mw64(rt + XHCI_RT_ERSTBA, erst_p);
        mw64(rt + XHCI_RT_ERDP, evt_p);

        mw32(op + XHCI_OP_CONFIG, max_slots.min(16) as u32);

        mw32(op + XHCI_OP_USBCMD, USBCMD_RS | USBCMD_INTE);
        spin(10000);

        if (mr32(op + XHCI_OP_USBSTS) & USBSTS_HCH) != 0 {
            serial::println(b"[USB] Start fail");
            return false;
        }

        serial::println(b"[USB] xHCI running");
        scan_ports(op, max_ports);
    }
    true
}

fn scan_ports(op: u64, max_ports: u8) {
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
                mw32(pa, (ps2 & !PORTSC_PLS_MASK) | PORTSC_PR | PORTSC_CSC | PORTSC_PRC | PORTSC_WRC);

                for _ in 0..500_000 {
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
                    spin(1);
                }
            }
        }
    }
}

fn enumerate_device(port: u8, speed: u8) -> bool {
    serial::print(b"[USB] Enum port ");
    serial::print_dec(port as u64);
    serial::println(b"");

    queue_cmd(0, 0, 0, TRB_TYPE_ENABLE_SLOT << 10);

    let slot = if let Some((33, code, _)) = wait_event(100_000) {
        if code != 1 {
            serial::println(b"[USB] EnableSlot fail");
            return false;
        }
        let ei = EVT_RING_IDX.load(Ordering::Relaxed);
        let pi = if ei == 0 { 255 } else { ei - 1 } as usize;
        unsafe { ((EVENT_RING.trbs[pi][3] >> 24) & 0xFF) as u8 }
    } else {
        serial::println(b"[USB] EnableSlot timeout");
        return false;
    };

    if slot == 0 || slot > 16 {
        serial::println(b"[USB] Bad slot");
        return false;
    }

    serial::print(b"[USB] Slot ");
    serial::print_dec(slot as u64);
    serial::println(b"");
    SLOT_ID.store(slot, Ordering::SeqCst);

    let max_pkt = match speed {
        1 => 8, 2 => 8, 3 => 64, 4 | 5 => 512, _ => 8
    };
    MAX_PACKET.store(max_pkt as u8, Ordering::SeqCst);

    unsafe {
        let input_ctx_ptr = addr_of_mut!(INPUT_CTX);
        for i in 0..8 { (*input_ctx_ptr).ctrl[i] = 0; (*input_ctx_ptr).slot[i] = 0; }
        for i in 0..31 { for j in 0..8 { (*input_ctx_ptr).ep[i][j] = 0; } }
        (*input_ctx_ptr).ctrl[1] = 0x03; // Add Slot + EP0
        (*input_ctx_ptr).slot[0] = ((speed as u32) << 20) | (1 << 27);
        (*input_ctx_ptr).slot[1] = (port as u32) << 16;

        let ep0_p = addr_of_mut!(EP0_RING) as u64;
        (*input_ctx_ptr).ep[0][1] = (3 << 1) | (4 << 3) | ((max_pkt as u32) << 16);
        (*input_ctx_ptr).ep[0][2] = (ep0_p & 0xFFFFFFFF) as u32 | 1;
        (*input_ctx_ptr).ep[0][3] = (ep0_p >> 32) as u32;
        (*input_ctx_ptr).ep[0][4] = 8;

        let dev_p = addr_of_mut!(DEV_CTX) as u64;
        let dcbaa_ptr = addr_of_mut!(DCBAA);
        (*dcbaa_ptr).entries[slot as usize] = dev_p;
    }

    let inp_p = addr_of_mut!(INPUT_CTX) as u64;
    queue_cmd((inp_p & 0xFFFFFFFF) as u32, (inp_p >> 32) as u32, 0,
              (TRB_TYPE_ADDRESS_DEVICE << 10) | ((slot as u32) << 24));

    if let Some((33, code, _)) = wait_event(100_000) {
        if code != 1 {
            serial::print(b"[USB] Addr fail ");
            serial::print_dec(code as u64);
            serial::println(b"");
            return false;
        }
    } else {
        serial::println(b"[USB] Addr timeout");
        return false;
    }

    serial::println(b"[USB] Device addressed");

    unsafe { for i in 0..64 { USB_BUF.data[i] = 0; } }
    if !get_descriptor(slot, super::transfer::USB_DESC_DEVICE, 0, 8) {
        serial::println(b"[USB] GetDevDesc8 fail");
    }

    unsafe { for i in 0..256 { USB_BUF.data[i] = 0; } }
    if !get_descriptor(slot, super::transfer::USB_DESC_CONFIGURATION, 0, 9) {
        serial::println(b"[USB] GetCfgDesc fail");
        return false;
    }

    let total_len = unsafe { (USB_BUF.data[2] as u16) | ((USB_BUF.data[3] as u16) << 8) };
    serial::print(b"[USB] Cfg len ");
    serial::print_dec(total_len as u64);
    serial::println(b"");

    unsafe { for i in 0..256 { USB_BUF.data[i] = 0; } }
    if !get_descriptor(slot, super::transfer::USB_DESC_CONFIGURATION, 0, total_len.min(255)) {
        serial::println(b"[USB] GetCfgDesc full fail");
        return false;
    }

    if let Some((cfg_val, iface, ep_info)) = parse_config_descriptor() {
        if !set_configuration(slot, cfg_val) {
            serial::println(b"[USB] SetCfg fail");
        }
        serial::println(b"[USB] Configuration set");

        if !set_protocol(slot, iface, 0) {
            serial::println(b"[USB] SetProto fail");
        }

        set_idle(slot, iface);

        let ep_num = ep_info.address & 0x0F;
        let ep_dci = ep_num * 2 + 1; // IN endpoint DCI
        HID_EP_ADDR.store(ep_info.address, Ordering::SeqCst);
        HID_EP_DCI.store(ep_dci, Ordering::SeqCst);
        HID_INTERVAL.store(ep_info.interval, Ordering::SeqCst);

        unsafe {
            let input_ctx_ptr = addr_of_mut!(INPUT_CTX);
            for i in 0..8 { (*input_ctx_ptr).ctrl[i] = 0; (*input_ctx_ptr).slot[i] = 0; }
            for i in 0..31 { for j in 0..8 { (*input_ctx_ptr).ep[i][j] = 0; } }

            (*input_ctx_ptr).ctrl[1] = 1 << (ep_dci as u32); // Add endpoint

            let dev_ctx_ptr = addr_of_mut!(DEV_CTX);
            for i in 0..8 { (*input_ctx_ptr).slot[i] = (*dev_ctx_ptr).slot[i]; }
            let ctx_entries = ep_dci.max(1);
            (*input_ctx_ptr).slot[0] = ((*input_ctx_ptr).slot[0] & 0x07FFFFFF) | ((ctx_entries as u32) << 27);

            let ep_idx = (ep_dci - 1) as usize;
            let hid_p = addr_of_mut!(HID_EP_RING) as u64;

            let interval_exp = ep_info.interval.saturating_sub(1).min(15);
            (*input_ctx_ptr).ep[ep_idx][0] = (interval_exp as u32) << 16; // Interval
            (*input_ctx_ptr).ep[ep_idx][1] = (3 << 1) | (7 << 3) | ((ep_info.max_packet as u32) << 16);
            (*input_ctx_ptr).ep[ep_idx][2] = (hid_p & 0xFFFFFFFF) as u32 | 1; // DCS=1
            (*input_ctx_ptr).ep[ep_idx][3] = (hid_p >> 32) as u32;
            (*input_ctx_ptr).ep[ep_idx][4] = ep_info.max_packet as u32; // Avg TRB Length
        }

        let inp_p = addr_of_mut!(INPUT_CTX) as u64;
        queue_cmd((inp_p & 0xFFFFFFFF) as u32, (inp_p >> 32) as u32, 0,
                  (TRB_TYPE_CONFIGURE_ENDPOINT << 10) | ((slot as u32) << 24));

        if let Some((33, code, _)) = wait_event(100_000) {
            if code != 1 {
                serial::print(b"[USB] CfgEP fail ");
                serial::print_dec(code as u64);
                serial::println(b"");
            } else {
                serial::println(b"[USB] Endpoint configured");

                let proto = unsafe {
                    let usb_buf_ptr = addr_of_mut!(USB_BUF);
                    (*usb_buf_ptr).data.iter().position(|&x| x == super::transfer::USB_DESC_INTERFACE)
                        .map(|i| (*usb_buf_ptr).data.get(i + 7).copied().unwrap_or(0)).unwrap_or(0)
                };

                if proto == 1 || ep_info.max_packet <= 8 {
                    KBD_AVAIL.store(true, Ordering::SeqCst);
                    serial::println(b"[USB] Keyboard ready");
                }
                if proto == 2 || (proto == 0 && ep_info.max_packet <= 8) {
                    MOUSE_AVAIL.store(true, Ordering::SeqCst);
                    serial::println(b"[USB] Mouse ready");
                }

                start_hid_poll();
                return true;
            }
        }
    }

    serial::println(b"[USB] No HID endpoint");
    false
}
