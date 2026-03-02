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


extern crate alloc;

use alloc::{string::{String, ToString}, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::{VirtAddr, PhysAddr};

use crate::memory::nonos_paging::{map_page, PagePermissions};

use super::types::*;

pub fn pci_config_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") address);
        let value: u32;
        core::arch::asm!("in eax, dx", out("eax") value, in("dx") 0xCFCu16);
        value
    }
}

pub fn pci_config_write(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address: u32 = (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xCF8u16, in("eax") address);
        core::arch::asm!("out dx, eax", in("dx") 0xCFCu16, in("eax") value);
    }
}

pub fn map_mmio_region(phys_addr: u64, size: usize) -> Option<u64> {
    let pages_needed = (size + 4095) / 4096;

    static NEXT_MMIO_ADDR: AtomicU64 = AtomicU64::new(0xFFFF_8900_0000_0000);
    let virt_base = NEXT_MMIO_ADDR.fetch_add((pages_needed * 4096) as u64, Ordering::SeqCst);

    for i in 0..pages_needed {
        let page_phys = PhysAddr::new(phys_addr + (i * 4096) as u64);
        let page_virt = VirtAddr::new(virt_base + (i * 4096) as u64);

        let permissions = PagePermissions::READ | PagePermissions::WRITE |
                         PagePermissions::NO_CACHE | PagePermissions::DEVICE;
        if let Err(_) = map_page(page_virt, page_phys, permissions) {
            return None;
        }
    }

    Some(virt_base)
}

pub fn scan_pci_for_nvme(controllers: &mut Vec<NvmeController>, namespaces: &mut Vec<NvmeNamespace>) {
    for bus in 0u8..=255 {
        for device in 0u8..32 {
            for function in 0u8..8 {
                let vendor_device = pci_config_read(bus, device, function, 0x00);
                let vendor_id = (vendor_device & 0xFFFF) as u16;
                let device_id = ((vendor_device >> 16) & 0xFFFF) as u16;

                if vendor_id == 0xFFFF {
                    continue;
                }

                let class_rev = pci_config_read(bus, device, function, 0x08);
                let class_code = ((class_rev >> 24) & 0xFF) as u8;
                let subclass = ((class_rev >> 16) & 0xFF) as u8;
                let prog_if = ((class_rev >> 8) & 0xFF) as u8;

                if class_code == 0x01 && subclass == 0x08 && prog_if == 0x02 {
                    let bar0_low = pci_config_read(bus, device, function, 0x10);
                    let bar0_high = pci_config_read(bus, device, function, 0x14);
                    let bar0_phys = ((bar0_high as u64) << 32) | (bar0_low as u64 & !0xF);

                    if bar0_phys != 0 {
                        let cmd = pci_config_read(bus, device, function, 0x04);
                        if (cmd & 0x4) == 0 {
                            pci_config_write(bus, device, function, 0x04, cmd | 0x4);
                        }

                        if let Some(ctrl) = probe_nvme_controller(bar0_phys, vendor_id, device_id, bus, device, function, namespaces) {
                            controllers.push(ctrl);
                        }
                    }
                }
            }
        }
    }
}

pub fn probe_nvme_controller(
    bar0_phys: u64,
    vendor_id: u16,
    device_id: u16,
    bus: u8,
    device: u8,
    function: u8,
    _namespaces: &mut Vec<NvmeNamespace>,
) -> Option<NvmeController> {
    let bar0_virt = match map_mmio_region(bar0_phys, 0x2000) {
        Some(v) => v,
        None => {
            crate::log::info!("nvme: Failed to map controller at {:x}", bar0_phys);
            return None;
        }
    };

    let regs = bar0_virt as *mut NvmeControllerRegs;

    unsafe {
        let cap = core::ptr::read_volatile(&(*regs).cap);
        let version = core::ptr::read_volatile(&(*regs).vs);
        let csts = core::ptr::read_volatile(&(*regs).csts);

        let max_queue_entries = ((cap & CAP_MQES_MASK) + 1) as u16;
        let doorbell_stride = 1u8 << ((cap >> CAP_DSTRD_SHIFT) & 0xF);
        let _timeout_500ms = ((cap & CAP_TO_MASK) >> CAP_TO_SHIFT) as u8;

        if (csts & CSTS_RDY) != 0 {
        } else {
        }

        let ctrl = NvmeController {
            vendor_id,
            device_id,
            bus,
            device,
            function,
            bar0_phys,
            bar0_virt,
            version,
            serial_number: String::new(),
            model_number: String::new(),
            firmware_rev: String::new(),
            max_transfer_size: 1 << (12 + 8), // Default MDTS
            num_namespaces: 0,
            max_queue_entries,
            doorbell_stride,
            controller_id: 0,
            total_capacity: 0,
        };


        Some(ctrl)
    }
}

pub fn parse_nvme_string(bytes: &[u8]) -> String {
    let trimmed: Vec<u8> = bytes.iter()
        .copied()
        .take_while(|&b| b != 0)
        .collect();

    String::from_utf8_lossy(&trimmed).trim().to_string()
}
