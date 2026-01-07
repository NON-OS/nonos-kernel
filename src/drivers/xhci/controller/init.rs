// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::ptr;
use core::sync::atomic::AtomicU64;
use alloc::boxed::Box;
use spin::Mutex;
use x86_64::VirtAddr;
use crate::drivers::pci::{self, PciDevice};
use crate::memory::mmio::{mmio_r32, mmio_w32, mmio_w64};
use super::super::constants::*;
use super::super::dma::DmaRegion;
use super::super::rings::{CommandRing, EventRing};
use super::super::stats::XhciStatistics;
use super::super::types::XhciConfig;
use super::completion::spin_wait;
use super::{XhciController, XHCI_CONTROLLER};

impl XhciController {
    pub fn init(pci: PciDevice) -> Result<&'static Mutex<Self>, &'static str> {
        let bar = pci.get_bar(0).ok_or("xHCI BAR0 not present")?;
        let (phys_addr, _) = bar.mmio_region().ok_or("xHCI BAR0 is not MMIO")?;
        let cap_base = phys_addr.as_u64() as usize;

        // SAFETY: cap_base points to valid MMIO region from BAR0
        let caplen_ver = unsafe { mmio_r32(VirtAddr::new((cap_base + CAP_CAPLENGTH) as u64)) };
        let caplen = (caplen_ver & 0xFF) as usize;
        let version = ((caplen_ver >> 16) & 0xFFFF) as u16;

        // SAFETY: reading capability registers from valid MMIO
        let hcs1 = unsafe { mmio_r32(VirtAddr::new((cap_base + CAP_HCSPARAMS1) as u64)) };
        let hcs2 = unsafe { mmio_r32(VirtAddr::new((cap_base + CAP_HCSPARAMS2) as u64)) };
        let hcc1 = unsafe { mmio_r32(VirtAddr::new((cap_base + CAP_HCCPARAMS1) as u64)) };
        let dboff = unsafe { mmio_r32(VirtAddr::new((cap_base + CAP_DBOFF) as u64)) };
        let rtsoff = unsafe { mmio_r32(VirtAddr::new((cap_base + CAP_RTSOFF) as u64)) };

        let op_base = cap_base + caplen;
        let db_base = cap_base + (dboff as usize);
        let rt_base = cap_base + (rtsoff as usize);

        let max_slots = (hcs1 & HCSPARAMS1_MAXSLOTS_MASK) as u8;
        let num_ports = ((hcs1 >> HCSPARAMS1_MAXPORTS_SHIFT) & 0xFF) as u8;
        let csz = (hcc1 & HCCPARAMS1_CSZ) != 0;

        crate::log::logger::log_critical(&alloc::format!(
            "xHCI: version {}.{}, {} slots, {} ports",
            version >> 8, version & 0xFF, max_slots, num_ports
        ));

        halt_controller(op_base)?;
        reset_controller(op_base)?;

        // SAFETY: writing to valid operational register
        unsafe { mmio_w32(VirtAddr::new((op_base + OP_PAGESIZE) as u64), 1); }

        let cmd_ring = CommandRing::new(DEFAULT_CMD_RING_SIZE).map_err(|e| e.as_str())?;
        let evt_ring = EventRing::new(DEFAULT_EVENT_RING_SIZE).map_err(|e| e.as_str())?;

        let dcbaa_bytes = ((max_slots as usize) + 1) * 8;
        let dcbaa = DmaRegion::new(dcbaa_bytes, true).map_err(|e| e.as_str())?;

        let max_scratch_hi = ((hcs2 >> HCSPARAMS2_SPB_HI_SHIFT) & 0x1F) as usize;
        let max_scratch_lo = ((hcs2 >> HCSPARAMS2_SPB_LO_SHIFT) & 0x1F) as usize;
        let max_scratch = max_scratch_lo | (max_scratch_hi << 5);

        let mut scratchpad_ptrs = None;
        let mut scratchpad_buffers = alloc::vec::Vec::new();

        if max_scratch > 0 {
            let arr_bytes = max_scratch * 8;
            let arr = DmaRegion::new(arr_bytes, true).map_err(|e| e.as_str())?;

            for i in 0..max_scratch {
                let buf = DmaRegion::new(4096, true).map_err(|e| e.as_str())?;
                // SAFETY: arr is valid DMA memory, i is within bounds
                unsafe {
                    let p = arr.as_mut_ptr::<u64>().add(i);
                    ptr::write_volatile(p, buf.phys());
                }
                scratchpad_buffers.push(buf);
            }

            // SAFETY: dcbaa is valid DMA memory
            unsafe {
                let p = dcbaa.as_mut_ptr::<u64>();
                ptr::write_volatile(p, arr.phys());
            }
            scratchpad_ptrs = Some(arr);
        }

        let device_contexts = (0..=max_slots as usize).map(|_| None).collect();

        // SAFETY: writing to valid operational registers
        unsafe { mmio_w64(VirtAddr::new((op_base + OP_DCBAAP) as u64), dcbaa.phys()); }

        // SAFETY: writing to valid operational registers
        unsafe {
            mmio_w64(VirtAddr::new((op_base + OP_CRCR) as u64), 0);
            mmio_w64(VirtAddr::new((op_base + OP_CRCR) as u64), cmd_ring.crcr_value());
        }

        // SAFETY: writing to valid runtime registers
        unsafe {
            mmio_w32(VirtAddr::new((rt_base + RT_IR0_ERSTSZ) as u64), 1);
            mmio_w64(VirtAddr::new((rt_base + RT_IR0_ERSTBA) as u64), evt_ring.erst_base_phys());
            mmio_w64(VirtAddr::new((rt_base + RT_IR0_ERDP) as u64), evt_ring.current_dequeue_phys());
            let iman = mmio_r32(VirtAddr::new((rt_base + RT_IR0_IMAN) as u64));
            mmio_w32(VirtAddr::new((rt_base + RT_IR0_IMAN) as u64), iman | IMAN_IE);
        }

        // SAFETY: writing to valid operational register
        unsafe { mmio_w32(VirtAddr::new((op_base + OP_CONFIG) as u64), max_slots as u32); }

        // SAFETY: writing to valid operational register
        unsafe {
            let usbcmd = mmio_r32(VirtAddr::new((op_base + OP_USBCMD) as u64));
            mmio_w32(VirtAddr::new((op_base + OP_USBCMD) as u64), usbcmd | USBCMD_INTE | USBCMD_RS);
        }

        let mut ctrl = XhciController {
            pci,
            cap_base,
            op_base,
            rt_base,
            db_base,
            max_slots,
            context_size_64: csz,
            num_ports,
            version,
            cmd_ring,
            evt_ring,
            dcbaa,
            scratchpad_ptrs,
            scratchpad_buffers,
            device_contexts,
            slot_id: 0,
            ep0_ring: None,
            config: XhciConfig::default(),
            stats: XhciStatistics::new(),
            last_enumeration_time: AtomicU64::new(0),
            enumeration_attempts: AtomicU64::new(0),
        };

        if let Err(e) = ctrl.enumerate_first_device() {
            crate::log::logger::log_critical(&alloc::format!("xHCI: Enumeration failed: {}", e));
        }

        let boxed = Box::leak(Box::new(Mutex::new(ctrl)));
        XHCI_CONTROLLER.call_once(|| boxed);
        Ok(boxed)
    }
}

pub fn halt_controller(op_base: usize) -> Result<(), &'static str> {
    // SAFETY: reading from valid operational register
    let mut cmd = unsafe { mmio_r32(VirtAddr::new((op_base + OP_USBCMD) as u64)) };
    cmd &= !USBCMD_RS;
    // SAFETY: writing to valid operational register
    unsafe { mmio_w32(VirtAddr::new((op_base + OP_USBCMD) as u64), cmd); }

    if !spin_wait(
        || {
            // SAFETY: reading from valid operational register
            let sts: u32 = unsafe { mmio_r32(VirtAddr::new((op_base + OP_USBSTS) as u64)) };
            (sts & USBSTS_HCH) != 0
        },
        CONTROLLER_RESET_TIMEOUT,
    ) {
        return Err("xHCI: HC did not halt");
    }
    Ok(())
}

pub fn reset_controller(op_base: usize) -> Result<(), &'static str> {
    // SAFETY: writing to valid operational register
    unsafe { mmio_w32(VirtAddr::new((op_base + OP_USBCMD) as u64), USBCMD_HCRST); }

    if !spin_wait(
        || {
            // SAFETY: reading from valid operational register
            let cmd: u32 = unsafe { mmio_r32(VirtAddr::new((op_base + OP_USBCMD) as u64)) };
            (cmd & USBCMD_HCRST) == 0
        },
        CONTROLLER_RESET_TIMEOUT,
    ) {
        return Err("xHCI: HCRST did not clear");
    }

    if !spin_wait(
        || {
            // SAFETY: reading from valid operational register
            let sts: u32 = unsafe { mmio_r32(VirtAddr::new((op_base + OP_USBSTS) as u64)) };
            (sts & USBSTS_CNR) == 0
        },
        CONTROLLER_RESET_TIMEOUT,
    ) {
        return Err("xHCI: Controller Not Ready stayed set");
    }

    Ok(())
}

pub fn init_xhci() -> Result<(), &'static str> {
    let devices = pci::scan_and_collect();
    let dev = devices
        .into_iter()
        .find(|d| d.class == XHCI_CLASS && d.subclass == XHCI_SUBCLASS && d.progif == XHCI_PROGIF)
        .ok_or("No xHCI controller found")?;

    let _ctrl = XhciController::init(dev)?;
    crate::log::logger::log_critical("xHCI: USB 3.0 subsystem initialized");
    Ok(())
}
