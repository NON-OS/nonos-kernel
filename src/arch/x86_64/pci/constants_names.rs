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

use super::constants_class as class_codes;

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
