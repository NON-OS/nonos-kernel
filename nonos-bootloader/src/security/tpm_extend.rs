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
use uefi::table::boot::SearchType;
use uefi::Identify;

use crate::log::logger::{log_debug, log_error, log_info, log_warn};

use super::tpm_types::{pcr, Tcg2EventHeader, Tcg2Protocol, EV_POST_CODE};

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

    const PE_COFF_IMAGE: u64 = 0x10;

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
