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

use core::ptr::NonNull;
use crate::drivers::pci::{pci_read_config32, PciBar, PciDevice};
use super::super::constants::*;
use super::common_cfg::VirtioPciCommonCfg;
use super::structure::VirtioModernRegs;

impl VirtioModernRegs {
    pub fn map(pci: &PciDevice) -> Option<Self> {
        let mut bar_bases: [Option<usize>; 6] = [None; 6];
        for i in 0..6 {
            if let Some(b) = pci.get_bar(i) {
                match b {
                    PciBar::Memory { address, .. } => bar_bases[i] = Some(address.as_u64() as usize),
                    PciBar::Memory32 { address, .. } => bar_bases[i] = Some(address.as_u64() as usize),
                    PciBar::Memory64 { address, .. } => bar_bases[i] = Some(address.as_u64() as usize),
                    PciBar::Io { .. } | PciBar::NotPresent => {}
                }
            }
        }
        let mut common: Option<NonNull<VirtioPciCommonCfg>> = None;
        let mut isr_ptr: Option<NonNull<u8>> = None;
        let mut notify_base = 0usize;
        let mut notify_mul = 0u32;
        let mut device_cfg = 0usize;
        for cap in pci.capabilities.iter().filter(|c| c.id == VIRTIO_PCI_CAP_VENDOR) {
            let hdr0 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset);
            let hdr1 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 4);
            let hdr2 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 8);
            let cap_len = ((hdr0 >> 16) & 0xFF) as u8;
            let cfg_type = ((hdr0 >> 24) & 0xFF) as u8;
            let bar = (hdr1 & 0xFF) as u8;
            let offset = (((hdr2 & 0xFFFF) as u64) << 16 | (hdr1 >> 16) as u64) as usize;
            let base = bar_bases.get(bar as usize).and_then(|x| *x).unwrap_or(0);
            if base == 0 { continue; }
            let mmio = base.wrapping_add(offset);
            match cfg_type {
                CAP_COMMON_CFG => common = NonNull::new(mmio as *mut VirtioPciCommonCfg),
                CAP_ISR_CFG => isr_ptr = NonNull::new(mmio as *mut u8),
                CAP_DEVICE_CFG => device_cfg = mmio,
                CAP_NOTIFY_CFG => {
                    notify_base = mmio;
                    if cap_len as usize >= 0x10 {
                        notify_mul = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 16);
                    }
                }
                _ => {}
            }
        }
        if let (Some(common), Some(isr_ptr)) = (common, isr_ptr) {
            if notify_base != 0 {
                return Some(Self { common, isr_ptr, notify_base, notify_off_multiplier: notify_mul, device_cfg, bar_bases });
            }
        }
        None
    }
}
