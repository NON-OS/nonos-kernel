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

use uefi::proto::unsafe_protocol;
use uefi::Status;

pub mod pcr {
    pub const BOOTLOADER: u32 = 8;
    pub const KERNEL: u32 = 9;
    pub const CAPSULE: u32 = 14;
}

pub const EV_POST_CODE: u32 = 0x00000001;

#[repr(C)]
#[unsafe_protocol("607f766c-7455-42be-930b-e4d76db2720f")]
pub struct Tcg2Protocol {
    pub get_capability: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        protocol_capability: *mut Tcg2BootServiceCapability,
    ) -> Status,
    pub get_event_log: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        event_log_format: u32,
        event_log_location: *mut u64,
        event_log_last_entry: *mut u64,
        event_log_truncated: *mut bool,
    ) -> Status,
    pub hash_log_extend_event: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        flags: u64,
        data_to_hash: *const u8,
        data_to_hash_len: u64,
        event: *const Tcg2EventHeader,
    ) -> Status,
    pub submit_command: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        input_parameter_block_size: u32,
        input_parameter_block: *const u8,
        output_parameter_block_size: u32,
        output_parameter_block: *mut u8,
    ) -> Status,
    pub get_active_pcr_banks:
        unsafe extern "efiapi" fn(this: *mut Tcg2Protocol, active_pcr_banks: *mut u32) -> Status,
    pub set_active_pcr_banks:
        unsafe extern "efiapi" fn(this: *mut Tcg2Protocol, active_pcr_banks: u32) -> Status,
    pub get_result_of_set_active_pcr_banks: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        operation_present: *mut u32,
        response: *mut u32,
    ) -> Status,
}

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

#[repr(C)]
pub struct Tcg2EventHeader {
    pub header_size: u32,
    pub header_version: u16,
    pub pcr_index: u32,
    pub event_type: u32,
}
