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

#[repr(C)]
pub struct Tcg2BootServiceCapability {
    pub size: u8,
    pub structure_version_major: u8,
    pub structure_version_minor: u8,
    pub protocol_version_major: u8,
    pub protocol_version_minor: u8,
    pub hash_algorithm_bitmap: u32,
    pub supported_event_logs: u32,
    pub tpm_present_flag: u8,
    pub max_command_size: u16,
    pub max_response_size: u16,
    pub manufacturer_id: u32,
    pub number_of_pcr_banks: u32,
    pub active_pcr_banks: u32,
}
