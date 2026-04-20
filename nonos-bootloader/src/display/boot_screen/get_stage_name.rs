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

pub fn get_stage_name(stage: u8) -> &'static str {
    match stage {
        0 => "Initializing UEFI Services",
        1 => "Loading Security Policies",
        2 => "Verifying Bootloader Signature",
        3 => "Setting Up Memory Protection",
        4 => "Initializing Cryptographic Subsystem",
        5 => "Loading Kernel Image",
        6 => "Verifying Kernel Signature",
        7 => "Setting Up Capability System",
        8 => "Starting Microkernel",
        9 => "Launching Userspace Services",
        _ => "Boot Complete",
    }
}