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

pub const VGA_TEXT_START: u64 = 0xB8000;
pub const VGA_TEXT_END: u64 = 0xC0000;
pub const LEGACY_VIDEO_START: u64 = 0xA0000;
pub const LEGACY_VIDEO_END: u64 = 0x100000;
pub const PCI_CONFIG_START: u64 = 0xC0000000;
pub const PCI_CONFIG_END: u64 = 0x100000000;
pub const IOAPIC_BASE: u64 = 0xFEC00000;
pub const IOAPIC_SIZE: u64 = 0x1000;
pub const LAPIC_BASE: u64 = 0xFEE00000;
pub const LAPIC_SIZE: u64 = 0x1000;
