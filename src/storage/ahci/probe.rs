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

use super::types::*;
use super::pci::{pci_config_read, map_mmio_region};

pub fn scan_pci_for_ahci(controllers: &mut Vec<AhciController>, ports: &mut Vec<AhciPort>) {
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

                if class_code == 0x01 && subclass == 0x06 && prog_if == 0x01 {
                    let bar5 = pci_config_read(bus, device, function, 0x24) as u64;

                    if bar5 != 0 && (bar5 & 0x1) == 0 {
                        let bar5_phys = bar5 & !0xF;

                        if let Some(ctrl) = probe_ahci_controller(bar5_phys, vendor_id, device_id, bus, device, function, ports) {
                            controllers.push(ctrl);
                        }
                    }
                }
            }
        }
    }
}

pub fn probe_ahci_controller(
    bar5_phys: u64,
    vendor_id: u16,
    device_id: u16,
    bus: u8,
    device: u8,
    function: u8,
    ports: &mut Vec<AhciPort>,
) -> Option<AhciController> {
    let bar5_virt = match map_mmio_region(bar5_phys, 0x1100) {
        Some(v) => v,
        None => {
            crate::log::info!("ahci: Failed to map HBA at {:x}", bar5_phys);
            return None;
        }
    };

    let hba = bar5_virt as *mut AhciHba;

    // SAFETY: HBA memory is properly mapped
    unsafe {
        let cap = core::ptr::read_volatile(&(*hba).cap);
        let cap2 = core::ptr::read_volatile(&(*hba).cap2);
        let version = core::ptr::read_volatile(&(*hba).vs);
        let pi = core::ptr::read_volatile(&(*hba).pi);
        let ghc = core::ptr::read_volatile(&(*hba).ghc);

        let supports_bios_handoff = (cap2 & 0x1) != 0;
        if supports_bios_handoff {
            crate::log::debug!("ahci: BIOS handoff supported");
        }

        if (ghc & GHC_AE) == 0 {
            core::ptr::write_volatile(&mut (*hba).ghc, ghc | GHC_AE);
            for _ in 0..100 {
                if (core::ptr::read_volatile(&(*hba).ghc) & GHC_AE) != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
        }

        let max_ports = ((cap >> 0) & 0x1F) as u8 + 1;
        let command_slots = ((cap >> 8) & 0x1F) as u8 + 1;
        let supports_64bit = (cap & HBA_CAP_S64A) != 0;
        let supports_ncq = (cap & HBA_CAP_NCQ) != 0;
        let supports_staggered = (cap & HBA_CAP_SSS) != 0;

        let ctrl = AhciController {
            vendor_id,
            device_id,
            bus,
            device,
            function,
            bar5_phys,
            bar5_virt,
            version,
            ports_implemented: pi,
            max_ports,
            command_slots,
            supports_64bit,
            supports_ncq,
            supports_staggered_spinup: supports_staggered,
        };

        for port_num in 0..32u8 {
            if (pi & (1 << port_num)) != 0 {
                if let Some(port_info) = probe_ahci_port(hba, port_num) {
                    ports.push(port_info);
                }
            }
        }

        Some(ctrl)
    }
}

pub unsafe fn probe_ahci_port(hba: *mut AhciHba, port_num: u8) -> Option<AhciPort> {
    // SAFETY: HBA memory is properly mapped, port_num is bounds checked
    unsafe {
        let port = &(*hba).ports[port_num as usize];

        let ssts = core::ptr::read_volatile(&port.ssts);
        let det = ssts & 0xF;
        let ipm = (ssts >> 8) & 0xF;

        if det != AHCI_HBA_PORT_DET_PRESENT || ipm != AHCI_HBA_PORT_IPM_ACTIVE {
            return None;
        }

        let sig = core::ptr::read_volatile(&port.sig);

        let device_type = match sig {
            AHCI_SIG_SATA => AhciDeviceType::Sata,
            AHCI_SIG_SATAPI => AhciDeviceType::Satapi,
            AHCI_SIG_SEMB => AhciDeviceType::EnclosureBridge,
            AHCI_SIG_PM => AhciDeviceType::PortMultiplier,
            _ => AhciDeviceType::None,
        };

        let mut port_info = AhciPort {
            port_num,
            device_type,
            signature: sig,
            sata_status: ssts,
            model: String::new(),
            serial: String::new(),
            firmware: String::new(),
            size_sectors: 0,
            sector_size: 512,
        };

        if device_type == AhciDeviceType::Sata {
            if let Some(identify_data) = send_identify_command(hba, port_num) {
                port_info.model = parse_ata_string(&identify_data[27..47]);
                port_info.serial = parse_ata_string(&identify_data[10..20]);
                port_info.firmware = parse_ata_string(&identify_data[23..27]);

                let lba48_sectors =
                    (identify_data[100] as u64) |
                    ((identify_data[101] as u64) << 16) |
                    ((identify_data[102] as u64) << 32) |
                    ((identify_data[103] as u64) << 48);

                if lba48_sectors > 0 {
                    port_info.size_sectors = lba48_sectors;
                } else {
                    port_info.size_sectors =
                        (identify_data[60] as u64) |
                        ((identify_data[61] as u64) << 16);
                }

                let physical_sector_size = identify_data[106];
                if (physical_sector_size & 0x1000) != 0 {
                    let exp = (physical_sector_size >> 8) & 0xF;
                    if exp > 0 {
                        port_info.sector_size = 512 << exp;
                    }
                }
            }
        }

        Some(port_info)
    }
}

pub unsafe fn send_identify_command(_hba: *mut AhciHba, _port_num: u8) -> Option<[u16; 256]> {
    None
}

pub fn parse_ata_string(words: &[u16]) -> String {
    let mut bytes = Vec::with_capacity(words.len() * 2);
    for &w in words {
        bytes.push((w >> 8) as u8);
        bytes.push(w as u8);
    }

    while bytes.last() == Some(&b' ') || bytes.last() == Some(&0) {
        bytes.pop();
    }

    String::from_utf8_lossy(&bytes).trim().to_string()
}
