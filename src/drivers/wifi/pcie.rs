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

use super::constants::{
    csr, csr_bits, APM_INIT_TIMEOUT_US, INT_COALESCING_TIMEOUT, NIC_ACCESS_TIMEOUT_US,
    STOP_MASTER_TIMEOUT_US, ALL_INTS_MASK, INT_MASK_DISABLED,
};
use super::error::WifiError;
use super::regs::WifiRegs;
use crate::drivers::pci::{pci_read_config32, pci_write_config32, PciDevice};
use x86_64::VirtAddr;

pub struct PcieTransport {
    pub pci_device: PciDevice,
    pub regs: WifiRegs,
    mmio_base: VirtAddr,
    mmio_size: usize,
    hw_rev: u32,
    hw_type: HwType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwType {
    Family7000,
    Family8000,
    Family9000,
    FamilyAx200,
    FamilyAx210,
    Unknown,
}

impl PcieTransport {
    pub fn new(pci_device: PciDevice) -> Result<Self, WifiError> {
        let bar0 = pci_device.get_bar(0).ok_or(WifiError::DeviceNotFound)?;
        let (mmio_base, mmio_size) = bar0.mmio_region().ok_or(WifiError::DeviceNotFound)?;

        let cmd = pci_read_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x04,
        );
        pci_write_config32(
            pci_device.bus,
            pci_device.device,
            pci_device.function,
            0x04,
            cmd | 0x06,
        );

        let mmio_virt = VirtAddr::new(mmio_base.as_u64());
        let regs = WifiRegs::new(mmio_virt);

        let hw_rev = regs.read32(csr::HW_REV);
        let hw_type = Self::detect_hw_type(pci_device.device_id_value(), hw_rev);

        crate::log::info!("iwlwifi: HW rev 0x{:08x}, type {:?}", hw_rev, hw_type);

        let mut trans = Self {
            pci_device,
            regs,
            mmio_base: mmio_virt,
            mmio_size,
            hw_rev,
            hw_type,
        };

        trans.apm_init()?;

        Ok(trans)
    }

    fn detect_hw_type(device_id: u16, _hw_rev: u32) -> HwType {
        match device_id {
            0x08B1..=0x08B4 | 0x095A | 0x095B => HwType::Family7000,
            0x24F3..=0x24FD => HwType::Family8000,
            0x2526 | 0x9DF0 | 0xA370 | 0x31DC | 0x30DC => HwType::Family9000,
            0x2723 | 0x2725 | 0x34F0 | 0x3DF0 | 0x4DF0 => HwType::FamilyAx200,
            0x2729 | 0x272B | 0x51F0 | 0x51F1 | 0x54F0 => HwType::FamilyAx210,
            _ => HwType::Unknown,
        }
    }

    fn apm_init(&mut self) -> Result<(), WifiError> {
        self.regs.set_bits(csr::GP_CNTRL, csr_bits::GP_CNTRL_XTAL_ON);
        self.udelay(10);

        self.regs.set_bits(
            csr::GP_CNTRL,
            csr_bits::GP_CNTRL_MAC_ACCESS_REQ | csr_bits::GP_CNTRL_INIT_DONE,
        );

        if !self.regs.poll(
            csr::GP_CNTRL,
            csr_bits::GP_CNTRL_MAC_CLOCK_READY,
            csr_bits::GP_CNTRL_MAC_CLOCK_READY,
            APM_INIT_TIMEOUT_US,
        ) {
            crate::log_warn!("iwlwifi: MAC clock not ready");
            return Err(WifiError::Timeout);
        }

        self.nic_init()?;

        Ok(())
    }

    fn nic_init(&mut self) -> Result<(), WifiError> {
        self.regs
            .write32(csr::INT_COALESCING, INT_COALESCING_TIMEOUT);
        self.regs.write32(csr::INT, ALL_INTS_MASK);
        self.regs.write32(csr::INT_MASK, INT_MASK_DISABLED);
        self.regs.write32(csr::FH_INT_STATUS, ALL_INTS_MASK);

        Ok(())
    }

    pub fn grab_nic_access(&self) -> Result<(), WifiError> {
        self.regs
            .set_bits(csr::GP_CNTRL, csr_bits::GP_CNTRL_MAC_ACCESS_REQ);

        if !self.regs.poll(
            csr::GP_CNTRL,
            csr_bits::GP_CNTRL_MAC_CLOCK_READY,
            csr_bits::GP_CNTRL_MAC_CLOCK_READY,
            NIC_ACCESS_TIMEOUT_US,
        ) {
            self.regs
                .clear_bits(csr::GP_CNTRL, csr_bits::GP_CNTRL_MAC_ACCESS_REQ);
            return Err(WifiError::Timeout);
        }

        Ok(())
    }

    pub fn release_nic_access(&self) {
        self.regs
            .clear_bits(csr::GP_CNTRL, csr_bits::GP_CNTRL_MAC_ACCESS_REQ);
    }

    pub fn read_prph(&self, addr: u32) -> Result<u32, WifiError> {
        self.grab_nic_access()?;
        let val = self.regs.read_prph(addr);
        self.release_nic_access();
        Ok(val)
    }

    pub fn write_prph(&self, addr: u32, val: u32) -> Result<(), WifiError> {
        self.grab_nic_access()?;
        self.regs.write_prph(addr, val);
        self.release_nic_access();
        Ok(())
    }

    pub fn stop_device(&mut self) {
        self.regs
            .set_bits(csr::RESET, csr_bits::RESET_REG_FLAG_STOP_MASTER);

        let _ = self.regs.poll(
            csr::RESET,
            csr_bits::RESET_REG_FLAG_MASTER_DISABLED,
            csr_bits::RESET_REG_FLAG_MASTER_DISABLED,
            STOP_MASTER_TIMEOUT_US,
        );

        self.regs
            .clear_bits(csr::GP_CNTRL, csr_bits::GP_CNTRL_MAC_ACCESS_REQ);

        self.regs.write32(csr::INT_MASK, INT_MASK_DISABLED);
        self.regs.write32(csr::INT, ALL_INTS_MASK);
        self.regs.write32(csr::FH_INT_STATUS, ALL_INTS_MASK);
    }

    pub fn sw_reset(&mut self) {
        self.regs
            .set_bits(csr::RESET, csr_bits::RESET_REG_FLAG_SW_RESET);
        self.udelay(10);
    }

    pub fn is_rf_kill(&self) -> bool {
        let val = self.regs.read32(csr::GP_CNTRL);
        (val & csr_bits::GP_CNTRL_INIT_DONE) == 0
    }

    pub fn hw_type(&self) -> HwType {
        self.hw_type
    }

    pub fn hw_rev(&self) -> u32 {
        self.hw_rev
    }

    pub fn enable_interrupts(&self, mask: u32) {
        self.regs.write32(csr::INT_MASK, mask);
    }

    pub fn disable_interrupts(&self) {
        self.regs.write32(csr::INT_MASK, 0);
    }

    pub fn ack_interrupts(&self) -> u32 {
        let inta = self.regs.read32(csr::INT);
        self.regs.write32(csr::INT, inta);
        inta
    }

    fn udelay(&self, us: u64) {
        let start = Self::timestamp();
        while Self::timestamp() - start < us {
            core::hint::spin_loop();
        }
    }

    fn timestamp() -> u64 {
        crate::arch::x86_64::time::tsc::elapsed_us()
    }
}
