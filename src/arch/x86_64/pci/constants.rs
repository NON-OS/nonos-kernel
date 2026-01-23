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

pub const MAX_PCI_BUSES: u16 = 256;
pub const MAX_DEVICES_PER_BUS: u8 = 32;
pub const MAX_FUNCTIONS_PER_DEVICE: u8 = 8;
pub const MAX_BARS: u8 = 6;

pub const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
pub const PCI_CONFIG_DATA: u16 = 0xCFC;

pub mod config {
    pub const VENDOR_ID: u16 = 0x00;
    pub const DEVICE_ID: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    pub const REVISION_ID: u16 = 0x08;
    pub const PROG_IF: u16 = 0x09;
    pub const SUBCLASS: u16 = 0x0A;
    pub const CLASS_CODE: u16 = 0x0B;
    pub const CACHE_LINE_SIZE: u16 = 0x0C;
    pub const LATENCY_TIMER: u16 = 0x0D;
    pub const HEADER_TYPE: u16 = 0x0E;
    pub const BIST: u16 = 0x0F;
    pub const BAR0: u16 = 0x10;
    pub const BAR1: u16 = 0x14;
    pub const BAR2: u16 = 0x18;
    pub const BAR3: u16 = 0x1C;
    pub const BAR4: u16 = 0x20;
    pub const BAR5: u16 = 0x24;
    pub const CARDBUS_CIS: u16 = 0x28;
    pub const SUBSYSTEM_VENDOR_ID: u16 = 0x2C;
    pub const SUBSYSTEM_ID: u16 = 0x2E;
    pub const EXPANSION_ROM: u16 = 0x30;
    pub const CAPABILITIES_PTR: u16 = 0x34;
    pub const INTERRUPT_LINE: u16 = 0x3C;
    pub const INTERRUPT_PIN: u16 = 0x3D;
    pub const MIN_GRANT: u16 = 0x3E;
    pub const MAX_LATENCY: u16 = 0x3F;
}

pub mod command {
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const SPECIAL_CYCLES: u16 = 1 << 3;
    pub const MWI_ENABLE: u16 = 1 << 4;
    pub const VGA_PALETTE_SNOOP: u16 = 1 << 5;
    pub const PARITY_ERROR_RESPONSE: u16 = 1 << 6;
    pub const SERR_ENABLE: u16 = 1 << 8;
    pub const FAST_B2B_ENABLE: u16 = 1 << 9;
    pub const INTERRUPT_DISABLE: u16 = 1 << 10;
}

pub mod status {
    pub const INTERRUPT_STATUS: u16 = 1 << 3;
    pub const CAPABILITIES_LIST: u16 = 1 << 4;
    pub const MHZ_66_CAPABLE: u16 = 1 << 5;
    pub const FAST_B2B_CAPABLE: u16 = 1 << 7;
    pub const MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
    pub const SIGNALED_TARGET_ABORT: u16 = 1 << 11;
    pub const RECEIVED_TARGET_ABORT: u16 = 1 << 12;
    pub const RECEIVED_MASTER_ABORT: u16 = 1 << 13;
    pub const SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
    pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
}

pub mod capability {
    pub const POWER_MANAGEMENT: u8 = 0x01;
    pub const AGP: u8 = 0x02;
    pub const VPD: u8 = 0x03;
    pub const SLOT_ID: u8 = 0x04;
    pub const MSI: u8 = 0x05;
    pub const HOT_SWAP: u8 = 0x06;
    pub const PCI_X: u8 = 0x07;
    pub const HYPERTRANSPORT: u8 = 0x08;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const DEBUG_PORT: u8 = 0x0A;
    pub const CPCI_CONTROL: u8 = 0x0B;
    pub const HOT_PLUG: u8 = 0x0C;
    pub const BRIDGE_SUBSYSTEM_VENDOR_ID: u8 = 0x0D;
    pub const AGP_8X: u8 = 0x0E;
    pub const SECURE_DEVICE: u8 = 0x0F;
    pub const PCI_EXPRESS: u8 = 0x10;
    pub const MSIX: u8 = 0x11;
    pub const SATA: u8 = 0x12;
    pub const AF: u8 = 0x13;
}

pub mod class_codes {
    pub const UNCLASSIFIED: u8 = 0x00;
    pub const STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const COMMUNICATION: u8 = 0x07;
    pub const SYSTEM: u8 = 0x08;
    pub const INPUT: u8 = 0x09;
    pub const DOCKING: u8 = 0x0A;
    pub const PROCESSOR: u8 = 0x0B;
    pub const SERIAL_BUS: u8 = 0x0C;
    pub const WIRELESS: u8 = 0x0D;
    pub const INTELLIGENT_IO: u8 = 0x0E;
    pub const SATELLITE: u8 = 0x0F;
    pub const ENCRYPTION: u8 = 0x10;
    pub const SIGNAL_PROCESSING: u8 = 0x11;
    pub const PROCESSING_ACCELERATOR: u8 = 0x12;
    pub const NON_ESSENTIAL: u8 = 0x13;
    pub const COPROCESSOR: u8 = 0x40;
    pub const UNASSIGNED: u8 = 0xFF;
}

pub fn get_class_name(class_code: u8) -> &'static str {
    match class_code {
        class_codes::UNCLASSIFIED => "Unclassified",
        class_codes::STORAGE => "Storage Controller",
        class_codes::NETWORK => "Network Controller",
        class_codes::DISPLAY => "Display Controller",
        class_codes::MULTIMEDIA => "Multimedia Controller",
        class_codes::MEMORY => "Memory Controller",
        class_codes::BRIDGE => "Bridge Device",
        class_codes::COMMUNICATION => "Communication Controller",
        class_codes::SYSTEM => "System Peripheral",
        class_codes::INPUT => "Input Device",
        class_codes::DOCKING => "Docking Station",
        class_codes::PROCESSOR => "Processor",
        class_codes::SERIAL_BUS => "Serial Bus Controller",
        class_codes::WIRELESS => "Wireless Controller",
        class_codes::INTELLIGENT_IO => "Intelligent I/O Controller",
        class_codes::SATELLITE => "Satellite Controller",
        class_codes::ENCRYPTION => "Encryption Controller",
        class_codes::SIGNAL_PROCESSING => "Signal Processing Controller",
        class_codes::PROCESSING_ACCELERATOR => "Processing Accelerator",
        class_codes::NON_ESSENTIAL => "Non-Essential Instrumentation",
        class_codes::COPROCESSOR => "Coprocessor",
        class_codes::UNASSIGNED => "Unassigned",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_offsets() {
        assert_eq!(config::VENDOR_ID, 0x00);
        assert_eq!(config::DEVICE_ID, 0x02);
        assert_eq!(config::BAR0, 0x10);
    }

    #[test]
    fn test_class_names() {
        assert_eq!(get_class_name(class_codes::STORAGE), "Storage Controller");
        assert_eq!(get_class_name(class_codes::NETWORK), "Network Controller");
    }
}
