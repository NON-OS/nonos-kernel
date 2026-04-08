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

pub mod header_type {
    pub const TYPE_MASK: u8 = 0x7F;
    pub const MULTI_FUNCTION: u8 = 0x80;
    pub const STANDARD: u8 = 0x00;
    pub const PCI_BRIDGE: u8 = 0x01;
    pub const CARDBUS_BRIDGE: u8 = 0x02;
}

pub mod capability_ids {
    pub const PM: u8 = 0x01;
    pub const AGP: u8 = 0x02;
    pub const VPD: u8 = 0x03;
    pub const SLOT_ID: u8 = 0x04;
    pub const MSI: u8 = 0x05;
    pub const COMPACT_PCI_HOT_SWAP: u8 = 0x06;
    pub const PCIX: u8 = 0x07;
    pub const HYPER_TRANSPORT: u8 = 0x08;
    pub const VENDOR_SPECIFIC: u8 = 0x09;
    pub const DEBUG_PORT: u8 = 0x0A;
    pub const COMPACT_PCI_RESOURCE: u8 = 0x0B;
    pub const HOT_PLUG: u8 = 0x0C;
    pub const BRIDGE_SUBSYSTEM_VENDOR: u8 = 0x0D;
    pub const AGP8X: u8 = 0x0E;
    pub const SECURE_DEVICE: u8 = 0x0F;
    pub const PCIE: u8 = 0x10;
    pub const MSIX: u8 = 0x11;
    pub const SATA: u8 = 0x12;
    pub const AF: u8 = 0x13;
}
