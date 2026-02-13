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

extern crate alloc;

use alloc::format;
use sha2::{Digest, Sha256};
use uefi::prelude::*;
use uefi::proto::unsafe_protocol;
use uefi::table::boot::SearchType;
use uefi::Identify;

use crate::log::logger::{log_debug, log_error, log_info, log_warn};

pub mod pcr {
    pub const BOOTLOADER: u32 = 8;
    pub const KERNEL: u32 = 9;
    pub const CAPSULE: u32 = 14;
}

const EV_POST_CODE: u32 = 0x00000001;

#[repr(C)]
#[unsafe_protocol("607f766c-7455-42be-930b-e4d76db2720f")]
struct Tcg2Protocol {
    get_capability: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        protocol_capability: *mut Tcg2BootServiceCapability,
    ) -> Status,
    get_event_log: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        event_log_format: u32,
        event_log_location: *mut u64,
        event_log_last_entry: *mut u64,
        event_log_truncated: *mut bool,
    ) -> Status,
    hash_log_extend_event: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        flags: u64,
        data_to_hash: *const u8,
        data_to_hash_len: u64,
        event: *const Tcg2EventHeader,
    ) -> Status,
    submit_command: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        input_parameter_block_size: u32,
        input_parameter_block: *const u8,
        output_parameter_block_size: u32,
        output_parameter_block: *mut u8,
    ) -> Status,
    get_active_pcr_banks:
        unsafe extern "efiapi" fn(this: *mut Tcg2Protocol, active_pcr_banks: *mut u32) -> Status,
    set_active_pcr_banks:
        unsafe extern "efiapi" fn(this: *mut Tcg2Protocol, active_pcr_banks: u32) -> Status,
    get_result_of_set_active_pcr_banks: unsafe extern "efiapi" fn(
        this: *mut Tcg2Protocol,
        operation_present: *mut u32,
        response: *mut u32,
    ) -> Status,
}

#[repr(C)]
struct Tcg2BootServiceCapability {
    size: u8,
    structure_version_major: u8,
    structure_version_minor: u8,
    protocol_version_major: u8,
    protocol_version_minor: u8,
    hash_algorithm_bitmap: u32,
    supported_event_logs: u32,
    tpm_present_flag: u8,
    max_command_size: u16,
    max_response_size: u16,
    manufacturer_id: u32,
    number_of_pcr_banks: u32,
    active_pcr_banks: u32,
}

#[repr(C)]
struct Tcg2EventHeader {
    header_size: u32,
    header_version: u16,
    pcr_index: u32,
    event_type: u32,
}

pub fn extend_pcr_measurement(
    system_table: &mut SystemTable<Boot>,
    pcr_index: u32,
    data: &[u8],
) -> bool {
    if data.is_empty() {
        log_warn("security", "empty data provided for PCR measurement");
        return false;
    }

    if pcr_index > 23 {
        log_error("security", "invalid PCR index (must be 0-23)");
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(data);
    let measurement: [u8; 32] = hasher.finalize().into();

    let bs = system_table.boot_services();

    match locate_tcg2_protocol(bs) {
        Some(tcg2) => match extend_pcr_via_tcg2(tcg2, pcr_index, &measurement) {
            Ok(()) => {
                log_info("security", &format!("PCR{} extended via TPM2", pcr_index));
                true
            }
            Err(e) => {
                log_warn("security", &format!("TPM2 PCR extend failed: {}", e));
                false
            }
        },
        None => {
            log_debug(
                "security",
                "no TPM2 available - measurement recorded but not extended",
            );
            false
        }
    }
}

fn locate_tcg2_protocol(bs: &uefi::table::boot::BootServices) -> Option<*mut Tcg2Protocol> {
    let handles = bs
        .locate_handle_buffer(SearchType::ByProtocol(&Tcg2Protocol::GUID))
        .ok()?;

    let handle = handles.first()?;

    let protocol = bs.open_protocol_exclusive::<Tcg2Protocol>(*handle).ok()?;

    let ptr = &*protocol as *const Tcg2Protocol as *mut Tcg2Protocol;

    core::mem::forget(protocol);

    Some(ptr)
}

fn extend_pcr_via_tcg2(
    tcg2: *mut Tcg2Protocol,
    pcr_index: u32,
    digest: &[u8; 32],
) -> Result<(), &'static str> {
    if tcg2.is_null() {
        return Err("TCG2 protocol handle is null");
    }

    let header = Tcg2EventHeader {
        header_size: core::mem::size_of::<Tcg2EventHeader>() as u32,
        header_version: 1,
        pcr_index,
        event_type: EV_POST_CODE,
    };

    // PE_COFF_IMAGE flag (0x10) indicates we're extending with pre-computed hash
    const PE_COFF_IMAGE: u64 = 0x10;

    // SAFETY: calling TCG2 protocol function through properly typed pointer
    unsafe {
        let status = ((*tcg2).hash_log_extend_event)(
            tcg2,
            PE_COFF_IMAGE,
            digest.as_ptr(),
            digest.len() as u64,
            &header,
        );

        if status.is_success() {
            Ok(())
        } else {
            Err("TCG2 HashLogExtendEvent failed")
        }
    }
}

pub fn measure_boot_components(
    system_table: &mut SystemTable<Boot>,
    bootloader_hash: &[u8],
    kernel_hash: &[u8],
    capsule_hash: &[u8],
) -> bool {
    let mut all_success = true;

    if !extend_pcr_measurement(system_table, pcr::BOOTLOADER, bootloader_hash) {
        log_debug("security", "bootloader measurement not extended (no TPM)");
        all_success = false;
    }

    if !extend_pcr_measurement(system_table, pcr::KERNEL, kernel_hash) {
        log_debug("security", "kernel measurement not extended (no TPM)");
        all_success = false;
    }

    if !extend_pcr_measurement(system_table, pcr::CAPSULE, capsule_hash) {
        log_debug("security", "capsule measurement not extended (no TPM)");
        all_success = false;
    }

    all_success
}
