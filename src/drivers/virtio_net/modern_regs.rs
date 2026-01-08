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
use crate::drivers::pci::{pci_read_config32, PciBar, PciDevice};
use super::constants::*;

#[repr(C, packed)]
pub struct VirtioPciCommonCfg {
    pub device_feature_select: u32,
    pub device_feature: u32,
    pub driver_feature_select: u32,
    pub driver_feature: u32,
    pub msix_config: u16,
    pub num_queues: u16,
    pub device_status: u8,
    pub config_generation: u8,
    pub queue_select: u16,
    pub queue_size: u16,
    pub queue_msix_vector: u16,
    pub queue_enable: u16,
    pub queue_notify_off: u16,
    pub queue_desc: u64,
    pub queue_avail: u64,
    pub queue_used: u64,
}

impl VirtioPciCommonCfg {
    pub const SIZE: usize = 64;
    pub unsafe fn read_device_features(ptr: *mut Self) -> u64 {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).device_feature_select), 0);
        let low = ptr::read_unaligned(ptr::addr_of!((*ptr).device_feature)) as u64;

        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).device_feature_select), 1);
        let high = ptr::read_unaligned(ptr::addr_of!((*ptr).device_feature)) as u64;

        low | (high << 32)
    }

    pub unsafe fn write_driver_features(ptr: *mut Self, features: u64) {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).driver_feature_select), 0);
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).driver_feature), features as u32);
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).driver_feature_select), 1);
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).driver_feature), (features >> 32) as u32);
    }

    pub unsafe fn read_status(ptr: *mut Self) -> u8 {
        ptr::read_unaligned(ptr::addr_of!((*ptr).device_status))
    }

    pub unsafe fn write_status(ptr: *mut Self, status: u8) {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).device_status), status);
    }

    pub unsafe fn read_num_queues(ptr: *mut Self) -> u16 {
        ptr::read_unaligned(ptr::addr_of!((*ptr).num_queues))
    }

    pub unsafe fn select_queue(ptr: *mut Self, queue: u16) {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_select), queue);
    }

    pub unsafe fn read_queue_size(ptr: *mut Self) -> u16 {
        ptr::read_unaligned(ptr::addr_of!((*ptr).queue_size))
    }

    pub unsafe fn write_queue_size(ptr: *mut Self, size: u16) {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_size), size);
    }

    pub unsafe fn enable_queue(ptr: *mut Self) {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_enable), 1);
    }

    pub unsafe fn read_queue_notify_off(ptr: *mut Self) -> u16 {
        ptr::read_unaligned(ptr::addr_of!((*ptr).queue_notify_off))
    }

    pub unsafe fn write_queue_addresses(
        ptr: *mut Self,
        desc: u64,
        avail: u64,
        used: u64,
    ) {
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_desc), desc);
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_avail), avail);
        ptr::write_unaligned(ptr::addr_of_mut!((*ptr).queue_used), used);
    }
}

pub struct VirtioModernRegs {
    pub common: core::ptr::NonNull<VirtioPciCommonCfg>,
    pub isr_ptr: core::ptr::NonNull<u8>,
    pub notify_base: usize,
    pub notify_off_multiplier: u32,
    pub device_cfg: usize,
    bar_bases: [Option<usize>; 6],
}

// SAFETY: VirtioModernRegs contains pointers to MMIO memory accessed through volatile operations
unsafe impl Send for VirtioModernRegs {}
unsafe impl Sync for VirtioModernRegs {}

impl VirtioModernRegs {
    pub fn map(pci: &PciDevice) -> Option<Self> {
        let mut bar_bases: [Option<usize>; 6] = [None; 6];
        for i in 0..6 {
            if let Some(b) = pci.get_bar(i) {
                match b {
                    PciBar::Memory { address, .. } => {
                        bar_bases[i] = Some(address.as_u64() as usize);
                    }
                    PciBar::Memory32 { address, .. } => {
                        bar_bases[i] = Some(address.as_u64() as usize);
                    }
                    PciBar::Memory64 { address, .. } => {
                        bar_bases[i] = Some(address.as_u64() as usize);
                    }
                    PciBar::Io { .. } => {}
                    PciBar::NotPresent => {}
                }
            }
        }

        let mut common: Option<core::ptr::NonNull<VirtioPciCommonCfg>> = None;
        let mut isr_ptr: Option<core::ptr::NonNull<u8>> = None;
        let mut notify_base = 0usize;
        let mut notify_mul = 0u32;
        let mut device_cfg = 0usize;

        for cap in pci.capabilities.iter().filter(|c| c.id == VIRTIO_PCI_CAP_VENDOR) {
            let cap_hdr0 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset);
            let cap_hdr1 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 4);
            let cap_hdr2 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 8);

            let cap_len = ((cap_hdr0 >> 16) & 0xFF) as u8;
            let cfg_type = ((cap_hdr0 >> 24) & 0xFF) as u8;
            let bar = (cap_hdr1 & 0xFF) as u8;
            let offset_low = cap_hdr1 >> 16;
            let offset_high = cap_hdr2 & 0xFFFF;
            let cfg_offset = ((offset_high as u64) << 16 | offset_low as u64) as usize;

            let base = bar_bases.get(bar as usize).and_then(|x| *x).unwrap_or(0);
            if base == 0 {
                continue;
            }

            let mmio = base.wrapping_add(cfg_offset);

            match cfg_type {
                CAP_COMMON_CFG => {
                    common = core::ptr::NonNull::new(mmio as *mut VirtioPciCommonCfg);
                }
                CAP_ISR_CFG => {
                    isr_ptr = core::ptr::NonNull::new(mmio as *mut u8);
                }
                CAP_DEVICE_CFG => {
                    device_cfg = mmio;
                }
                CAP_NOTIFY_CFG => {
                    notify_base = mmio;
                    if cap_len as usize >= 0x10 {
                        notify_mul = pci_read_config32(
                            pci.bus,
                            pci.device,
                            pci.function,
                            cap.offset + 16,
                        );
                    }
                }
                _ => {}
            }
        }

        if let (Some(common), Some(isr_ptr)) = (common, isr_ptr) {
            if notify_base != 0 {
                Some(Self {
                    common,
                    isr_ptr,
                    notify_base,
                    notify_off_multiplier: notify_mul,
                    device_cfg,
                    bar_bases,
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn common_ptr(&self) -> *mut VirtioPciCommonCfg {
        self.common.as_ptr()
    }

    pub fn read_device_features(&self) -> u64 {
        // SAFETY: common pointer is valid MMIO memory
        unsafe { VirtioPciCommonCfg::read_device_features(self.common.as_ptr()) }
    }

    pub fn write_driver_features(&self, features: u64) {
        // SAFETY: common pointer is valid MMIO memory
        unsafe { VirtioPciCommonCfg::write_driver_features(self.common.as_ptr(), features) }
    }

    pub fn read_status(&self) -> u8 {
        // SAFETY: common pointer is valid MMIO memory
        unsafe { VirtioPciCommonCfg::read_status(self.common.as_ptr()) }
    }

    pub fn write_status(&self, status: u8) {
        // SAFETY: common pointer is valid MMIO memory
        unsafe { VirtioPciCommonCfg::write_status(self.common.as_ptr(), status) }
    }

    pub fn set_status_bit(&self, bit: u8) {
        let current = self.read_status();
        self.write_status(current | bit);
    }

    pub fn read_isr(&self) -> u8 {
        // SAFETY: isr_ptr is valid MMIO memory
        unsafe { ptr::read_volatile(self.isr_ptr.as_ptr()) }
    }

    pub fn read_device_cfg_byte(&self, offset: usize) -> u8 {
        if self.device_cfg == 0 {
            return 0;
        }
        // SAFETY: device_cfg points to valid MMIO memory
        unsafe { ptr::read_volatile((self.device_cfg + offset) as *const u8) }
    }

    pub fn read_device_cfg_u16(&self, offset: usize) -> u16 {
        if self.device_cfg == 0 {
            return 0;
        }
        // SAFETY: device_cfg points to valid MMIO memory
        unsafe { ptr::read_volatile((self.device_cfg + offset) as *const u16) }
    }

    pub fn read_mac_address(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = self.read_device_cfg_byte(i);
        }
        mac
    }

    pub fn queue_notify_addr(&self, notify_off: u16) -> usize {
        self.notify_base + (notify_off as usize) * (self.notify_off_multiplier as usize)
    }

    pub fn setup_queue(
        &self,
        queue_idx: u16,
        desc_addr: u64,
        avail_addr: u64,
        used_addr: u64,
        queue_size: u16,
    ) -> Result<u16, &'static str> {
        // SAFETY: common pointer is valid MMIO memory
        unsafe {
            let ptr = self.common.as_ptr();

            VirtioPciCommonCfg::select_queue(ptr, queue_idx);

            let max_size = VirtioPciCommonCfg::read_queue_size(ptr);
            if max_size == 0 {
                return Err("virtio: queue not available");
            }

            let actual_size = core::cmp::min(queue_size, max_size);
            VirtioPciCommonCfg::write_queue_size(ptr, actual_size);

            VirtioPciCommonCfg::write_queue_addresses(ptr, desc_addr, avail_addr, used_addr);

            VirtioPciCommonCfg::enable_queue(ptr);

            let notify_off = VirtioPciCommonCfg::read_queue_notify_off(ptr);

            Ok(notify_off)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_cfg_size() {
        assert_eq!(VirtioPciCommonCfg::SIZE, 64);
    }
}
