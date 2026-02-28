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

use core::slice;
use x86_64::PhysAddr;

use crate::arch::x86_64::multiboot::error::MultibootError;
use crate::arch::x86_64::multiboot::modules::{AcpiRsdp, ApmTable, SmbiosInfo};
use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_apm(
        &self,
        tag_ptr: *const u8,
    ) -> Option<ApmTable> {
        // SAFETY: Caller guarantees tag_ptr points to valid APM tag.
        unsafe {
            #[repr(C)]
            struct ApmTag {
                tag_type: u32,
                size: u32,
                version: u16,
                cseg: u16,
                offset: u32,
                cseg_16: u16,
                dseg: u16,
                flags: u16,
                cseg_len: u16,
                cseg_16_len: u16,
                dseg_len: u16,
            }

            let tag = &*(tag_ptr as *const ApmTag);
            Some(ApmTable {
                version: tag.version,
                cseg: tag.cseg,
                offset: tag.offset,
                cseg_16: tag.cseg_16,
                dseg: tag.dseg,
                flags: tag.flags,
                cseg_len: tag.cseg_len,
                cseg_16_len: tag.cseg_16_len,
                dseg_len: tag.dseg_len,
            })
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_acpi_rsdp(
        &self,
        tag_ptr: *const u8,
        size: u32,
        is_new: bool,
    ) -> Result<AcpiRsdp, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid ACPI RSDP tag.
        unsafe {
            let rsdp_ptr = tag_ptr.add(8);
            let rsdp_size = size.saturating_sub(8) as usize;

            if rsdp_size < 20 {
                return Err(MultibootError::AcpiError {
                    reason: "RSDP too small",
                });
            }

            let mut signature = [0u8; 8];
            signature.copy_from_slice(slice::from_raw_parts(rsdp_ptr, 8));

            if &signature != b"RSD PTR " {
                return Err(MultibootError::AcpiError {
                    reason: "Invalid RSDP signature",
                });
            }

            let mut oem_id = [0u8; 6];
            oem_id.copy_from_slice(slice::from_raw_parts(rsdp_ptr.add(9), 6));

            let checksum = *rsdp_ptr.add(8);
            let revision = *rsdp_ptr.add(15);
            let rsdt_address = *(rsdp_ptr.add(16) as *const u32);

            let (length, xsdt_address, extended_checksum) = if is_new && rsdp_size >= 36 {
                let length = *(rsdp_ptr.add(20) as *const u32);
                let xsdt_address = *(rsdp_ptr.add(24) as *const u64);
                let extended_checksum = *rsdp_ptr.add(32);
                (Some(length), Some(xsdt_address), Some(extended_checksum))
            } else {
                (None, None, None)
            };

            Ok(AcpiRsdp {
                signature,
                checksum,
                oem_id,
                revision,
                rsdt_address,
                length,
                xsdt_address,
                extended_checksum,
            })
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_smbios(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<SmbiosInfo, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid SMBIOS tag.
        unsafe {
            if size < 16 {
                return Err(MultibootError::SmbiosError {
                    reason: "Tag too small",
                });
            }

            #[repr(C)]
            struct SmbiosTag {
                tag_type: u32,
                size: u32,
                major: u8,
                minor: u8,
                reserved: [u8; 6],
            }

            let tag = &*(tag_ptr as *const SmbiosTag);

            let table_ptr = tag_ptr.add(16);
            let table_size = size.saturating_sub(16);

            Ok(SmbiosInfo {
                major_version: tag.major,
                minor_version: tag.minor,
                table_address: PhysAddr::new(table_ptr as u64),
                table_length: table_size,
            })
        }
    }
}
