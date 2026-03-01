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

use super::controller::DesignWareI2c;
use super::error::I2cError;
use super::CONTROLLERS;
use alloc::vec::Vec;

const INTEL_VENDOR_ID: u16 = 0x8086;

const LPSS_I2C_DEVICE_IDS: &[(u16, &str, u32)] = &[
    (0x9D60, "Sunrise Point-LP I2C #0", 120_000_000),
    (0x9D61, "Sunrise Point-LP I2C #1", 120_000_000),
    (0x9D62, "Sunrise Point-LP I2C #2", 120_000_000),
    (0x9D63, "Sunrise Point-LP I2C #3", 120_000_000),
    (0x9D64, "Sunrise Point-LP I2C #4", 120_000_000),
    (0x9D65, "Sunrise Point-LP I2C #5", 120_000_000),
    (0xA160, "Sunrise Point-H I2C #0", 120_000_000),
    (0xA161, "Sunrise Point-H I2C #1", 120_000_000),
    (0xA162, "Sunrise Point-H I2C #2", 120_000_000),
    (0xA163, "Sunrise Point-H I2C #3", 120_000_000),
    (0x9DE8, "Cannon Point-LP I2C #0", 120_000_000),
    (0x9DE9, "Cannon Point-LP I2C #1", 120_000_000),
    (0x9DEA, "Cannon Point-LP I2C #2", 120_000_000),
    (0x9DEB, "Cannon Point-LP I2C #3", 120_000_000),
    (0xA368, "Cannon Lake-H I2C #0", 120_000_000),
    (0xA369, "Cannon Lake-H I2C #1", 120_000_000),
    (0xA36A, "Cannon Lake-H I2C #2", 120_000_000),
    (0xA36B, "Cannon Lake-H I2C #3", 120_000_000),
    (0x02E8, "Comet Lake I2C #0", 120_000_000),
    (0x02E9, "Comet Lake I2C #1", 120_000_000),
    (0x02EA, "Comet Lake I2C #2", 120_000_000),
    (0x02EB, "Comet Lake I2C #3", 120_000_000),
    (0x06E8, "Comet Lake-H I2C #0", 120_000_000),
    (0x06E9, "Comet Lake-H I2C #1", 120_000_000),
    (0x06EA, "Comet Lake-H I2C #2", 120_000_000),
    (0x06EB, "Comet Lake-H I2C #3", 120_000_000),
    (0xA0E8, "Tiger Lake-LP I2C #0", 100_000_000),
    (0xA0E9, "Tiger Lake-LP I2C #1", 100_000_000),
    (0xA0EA, "Tiger Lake-LP I2C #2", 100_000_000),
    (0xA0EB, "Tiger Lake-LP I2C #3", 100_000_000),
    (0xA0C5, "Tiger Lake-LP I2C #4", 100_000_000),
    (0xA0C6, "Tiger Lake-LP I2C #5", 100_000_000),
    (0x43E8, "Tiger Lake-H I2C #0", 100_000_000),
    (0x43E9, "Tiger Lake-H I2C #1", 100_000_000),
    (0x43EA, "Tiger Lake-H I2C #2", 100_000_000),
    (0x43EB, "Tiger Lake-H I2C #3", 100_000_000),
    (0x51E8, "Alder Lake-P I2C #0", 100_000_000),
    (0x51E9, "Alder Lake-P I2C #1", 100_000_000),
    (0x51EA, "Alder Lake-P I2C #2", 100_000_000),
    (0x51EB, "Alder Lake-P I2C #3", 100_000_000),
    (0x51C5, "Alder Lake-P I2C #4", 100_000_000),
    (0x51C6, "Alder Lake-P I2C #5", 100_000_000),
    (0x7AE8, "Alder Lake-S I2C #0", 100_000_000),
    (0x7AE9, "Alder Lake-S I2C #1", 100_000_000),
    (0x7AEA, "Alder Lake-S I2C #2", 100_000_000),
    (0x7AEB, "Alder Lake-S I2C #3", 100_000_000),
    (0x7AF8, "Alder Lake-S I2C #4", 100_000_000),
    (0x7AF9, "Alder Lake-S I2C #5", 100_000_000),
    (0xA0D8, "Raptor Lake-P I2C #0", 100_000_000),
    (0xA0D9, "Raptor Lake-P I2C #1", 100_000_000),
    (0xA0DA, "Raptor Lake-P I2C #2", 100_000_000),
    (0xA0DB, "Raptor Lake-P I2C #3", 100_000_000),
    (0xA0DC, "Raptor Lake-P I2C #4", 100_000_000),
    (0xA0DD, "Raptor Lake-P I2C #5", 100_000_000),
    (0x7A4C, "Raptor Lake-S I2C #0", 100_000_000),
    (0x7A4D, "Raptor Lake-S I2C #1", 100_000_000),
    (0x7A4E, "Raptor Lake-S I2C #2", 100_000_000),
    (0x7A4F, "Raptor Lake-S I2C #3", 100_000_000),
    (0x7A7C, "Raptor Lake-S I2C #4", 100_000_000),
    (0x7A7D, "Raptor Lake-S I2C #5", 100_000_000),
    (0x54E8, "Alder Lake-N I2C #0", 100_000_000),
    (0x54E9, "Alder Lake-N I2C #1", 100_000_000),
    (0x54EA, "Alder Lake-N I2C #2", 100_000_000),
    (0x54EB, "Alder Lake-N I2C #3", 100_000_000),
    (0x7E50, "Meteor Lake-P I2C #0", 100_000_000),
    (0x7E51, "Meteor Lake-P I2C #1", 100_000_000),
    (0x7E52, "Meteor Lake-P I2C #2", 100_000_000),
    (0x7E78, "Meteor Lake-P I2C #3", 100_000_000),
    (0x7E79, "Meteor Lake-P I2C #4", 100_000_000),
    (0x7E7A, "Meteor Lake-P I2C #5", 100_000_000),
    (0x34E8, "Ice Lake-LP I2C #0", 100_000_000),
    (0x34E9, "Ice Lake-LP I2C #1", 100_000_000),
    (0x34EA, "Ice Lake-LP I2C #2", 100_000_000),
    (0x34EB, "Ice Lake-LP I2C #3", 100_000_000),
    (0x34C5, "Ice Lake-LP I2C #4", 100_000_000),
    (0x34C6, "Ice Lake-LP I2C #5", 100_000_000),
    (0x4DE8, "Jasper Lake I2C #0", 100_000_000),
    (0x4DE9, "Jasper Lake I2C #1", 100_000_000),
    (0x4DEA, "Jasper Lake I2C #2", 100_000_000),
    (0x4DEB, "Jasper Lake I2C #3", 100_000_000),
    (0x4DC5, "Jasper Lake I2C #4", 100_000_000),
    (0x4DC6, "Jasper Lake I2C #5", 100_000_000),
    (0x5AC2, "Broxton I2C #0", 100_000_000),
    (0x5AC4, "Broxton I2C #1", 100_000_000),
    (0x5AC6, "Broxton I2C #2", 100_000_000),
    (0x5AEE, "Broxton I2C #3", 100_000_000),
    (0x1AC2, "Broxton-P I2C #0", 100_000_000),
    (0x1AC4, "Broxton-P I2C #1", 100_000_000),
    (0x1AC6, "Broxton-P I2C #2", 100_000_000),
    (0x1AEE, "Broxton-P I2C #3", 100_000_000),
    (0x31AC, "Gemini Lake I2C #0", 100_000_000),
    (0x31AE, "Gemini Lake I2C #1", 100_000_000),
    (0x31B0, "Gemini Lake I2C #2", 100_000_000),
    (0x31B2, "Gemini Lake I2C #3", 100_000_000),
    (0x31B4, "Gemini Lake I2C #4", 100_000_000),
    (0x31B6, "Gemini Lake I2C #5", 100_000_000),
    (0x31B8, "Gemini Lake I2C #6", 100_000_000),
    (0x31BA, "Gemini Lake I2C #7", 100_000_000),
];

#[derive(Clone)]
pub struct LpssController {
    inner: DesignWareI2c,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub device_id: u16,
    pub name: &'static str,
    pub index: usize,
}

impl LpssController {
    pub fn read(&self, addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), I2cError> {
        self.inner.read(addr, reg, buf)
    }

    pub fn write(&self, addr: u8, reg: u8, data: &[u8]) -> Result<(), I2cError> {
        self.inner.write(addr, reg, data)
    }

    pub fn write_read(
        &self,
        addr: u8,
        write_data: &[u8],
        read_buf: &mut [u8],
    ) -> Result<(), I2cError> {
        self.inner.write_read(addr, write_data, read_buf)
    }

    pub fn probe(&self, addr: u8) -> bool {
        self.inner.probe(addr)
    }

    pub fn base_address(&self) -> u64 {
        self.inner.base_address()
    }
}

pub fn find_lpss_controllers() -> Vec<LpssController> {
    use crate::drivers::pci::config::ConfigSpace;
    use crate::drivers::pci::types::PciBar;

    let mut controllers = Vec::new();
    let pci_devices = crate::drivers::pci::scan_and_collect();

    for pci_dev in pci_devices {
        if pci_dev.vendor_id() != INTEL_VENDOR_ID {
            continue;
        }

        let device_id = pci_dev.device_id_value();

        if let Some((_, name, clock)) = LPSS_I2C_DEVICE_IDS
            .iter()
            .find(|(id, _, _)| *id == device_id)
        {
            let base = match &pci_dev.bars[0] {
                PciBar::Memory32 { address, .. } => address.as_u64(),
                PciBar::Memory64 { address, .. } => address.as_u64(),
                PciBar::Memory { address, .. } => address.as_u64(),
                _ => continue,
            };

            if base == 0 {
                continue;
            }

            let config = ConfigSpace::new(pci_dev.address);
            let _ = config.set_power_state_d0();
            let _ = config.enable_bus_master();
            let _ = config.enable_memory_space();

            let mut dw = match DesignWareI2c::new(base, *clock) {
                Some(d) => d,
                None => {
                    crate::log_warn!("i2c: Failed to map MMIO at 0x{:x}", base);
                    continue;
                }
            };

            if dw.init().is_ok() {
                let index = controllers.len();
                controllers.push(LpssController {
                    inner: dw,
                    bus: pci_dev.bus(),
                    device: pci_dev.device(),
                    function: pci_dev.function(),
                    device_id,
                    name,
                    index,
                });

                crate::log::info!(
                    "i2c: Found {} at {:02x}:{:02x}.{} (BAR 0x{:x})",
                    name,
                    pci_dev.bus(),
                    pci_dev.device(),
                    pci_dev.function(),
                    base
                );
            }
        }
    }

    controllers
}

pub fn init() -> usize {
    let controllers = find_lpss_controllers();
    let count = controllers.len();

    let mut global = CONTROLLERS.lock();
    *global = controllers;

    if count > 0 {
        crate::log::info!("i2c: Initialized {} Intel LPSS I2C controller(s)", count);
    }

    count
}

pub fn scan_bus(controller: usize) -> Vec<u8> {
    let mut found = Vec::new();

    if let Some(ctrl) = super::get_controller(controller) {
        for addr in 0x08..0x78 {
            if ctrl.probe(addr) {
                found.push(addr);
            }
        }
    }

    found
}

const KNOWN_TOUCHPAD_ADDRS: &[u8] = &[
    0x10, // ELAN alternate
    0x15, // ELAN (most common on HP laptops)
    0x2C, // Synaptics
    0x38, // FocalTech
    0x4B, // Synaptics alternate
    0x4C, // Synaptics alternate
    0x20, // Some Elan devices
    0x24, // Some multi-touch
];

pub fn detect_hid_devices() -> Vec<(usize, u8)> {
    let mut hid_devices = Vec::new();

    let count = super::controller_count();
    crate::log::info!("i2c: Scanning {} controller(s) for HID devices", count);

    for ctrl_idx in 0..count {
        for &addr in KNOWN_TOUCHPAD_ADDRS {
            if let Some(ctrl) = super::get_controller(ctrl_idx) {
                if ctrl.probe(addr) {
                    crate::log::info!("i2c: Found device at bus {} addr 0x{:02x}", ctrl_idx, addr);
                    if is_hid_device(ctrl_idx, addr) {
                        hid_devices.push((ctrl_idx, addr));
                        crate::log::info!("i2c: Confirmed HID at bus {} addr 0x{:02x}", ctrl_idx, addr);
                    } else {
                        if is_hid_device_relaxed(ctrl_idx, addr) {
                            hid_devices.push((ctrl_idx, addr));
                            crate::log::info!("i2c: HID (relaxed) at bus {} addr 0x{:02x}", ctrl_idx, addr);
                        }
                    }
                }
            }
        }

        let addresses = scan_bus(ctrl_idx);
        for addr in addresses {
            if hid_devices.iter().any(|(c, a)| *c == ctrl_idx && *a == addr) {
                continue;
            }
            if is_hid_device(ctrl_idx, addr) {
                hid_devices.push((ctrl_idx, addr));
                crate::log::info!("i2c: Found HID device at bus {} addr 0x{:02x}", ctrl_idx, addr);
            }
        }
    }

    if hid_devices.is_empty() {
        crate::log::info!("i2c: No HID devices found on {} controllers", count);
    }

    hid_devices
}

fn is_hid_device(controller: usize, addr: u8) -> bool {
    let ctrl = match super::get_controller(controller) {
        Some(c) => c,
        None => return false,
    };

    let mut desc_addr = [0u8; 2];
    if ctrl.write_read(addr, &[0x01, 0x00], &mut desc_addr).is_err() {
        return false;
    }

    let mut hid_desc = [0u8; 30];
    if ctrl.write_read(addr, &[0x01, 0x00], &mut hid_desc).is_err() {
        return false;
    }

    let desc_len = u16::from_le_bytes([hid_desc[0], hid_desc[1]]);
    if desc_len < 30 || desc_len > 256 {
        return false;
    }

    let bcd_version = u16::from_le_bytes([hid_desc[2], hid_desc[3]]);
    if bcd_version != 0x0100 {
        return false;
    }

    true
}

fn is_hid_device_relaxed(controller: usize, addr: u8) -> bool {
    let ctrl = match super::get_controller(controller) {
        Some(c) => c,
        None => return false,
    };

    let mut hid_desc = [0u8; 30];
    if ctrl.write_read(addr, &[0x01, 0x00], &mut hid_desc).is_ok() {
        let desc_len = u16::from_le_bytes([hid_desc[0], hid_desc[1]]);
        let bcd_version = u16::from_le_bytes([hid_desc[2], hid_desc[3]]);

        if desc_len >= 28 && desc_len <= 256 {
            if bcd_version >= 0x0100 && bcd_version <= 0x0111 {
                crate::log::info!(
                    "i2c: Relaxed HID match at 0x{:02x}: len={}, ver=0x{:04x}",
                    addr, desc_len, bcd_version
                );
                return true;
            }
        }

        if desc_len >= 20 {
            let report_desc_len = u16::from_le_bytes([hid_desc[4], hid_desc[5]]);
            let report_desc_reg = u16::from_le_bytes([hid_desc[6], hid_desc[7]]);
            if report_desc_len > 0 && report_desc_len < 4096 && report_desc_reg != 0 {
                crate::log::info!(
                    "i2c: ELAN-style HID at 0x{:02x}: rdesc_len={}, rdesc_reg=0x{:04x}",
                    addr, report_desc_len, report_desc_reg
                );
                return true;
            }
        }
    }

    for desc_reg in &[0x0020u16, 0x0021, 0x0030] {
        let reg_bytes = desc_reg.to_le_bytes();
        if ctrl.write_read(addr, &reg_bytes, &mut hid_desc).is_ok() {
            let desc_len = u16::from_le_bytes([hid_desc[0], hid_desc[1]]);
            if desc_len >= 28 && desc_len <= 256 {
                crate::log::info!(
                    "i2c: Alternate HID at 0x{:02x} reg 0x{:04x}: len={}",
                    addr, desc_reg, desc_len
                );
                return true;
            }
        }
    }

    false
}
