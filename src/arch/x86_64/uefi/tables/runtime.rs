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

use crate::arch::x86_64::uefi::constants::RUNTIME_SERVICES_SIGNATURE;
use crate::arch::x86_64::uefi::error::UefiError;
use crate::arch::x86_64::uefi::types::Guid;
use super::header::TableHeader;
use super::time::{EfiTime, EfiTimeCapabilities};

#[repr(C)]
pub struct RuntimeServices {
    pub header: TableHeader,
    pub get_time: extern "efiapi" fn(*mut EfiTime, *mut EfiTimeCapabilities) -> u64,
    pub set_time: extern "efiapi" fn(*const EfiTime) -> u64,
    pub get_wakeup_time: extern "efiapi" fn(*mut u8, *mut u8, *mut EfiTime) -> u64,
    pub set_wakeup_time: extern "efiapi" fn(u8, *const EfiTime) -> u64,
    pub set_virtual_address_map: extern "efiapi" fn(u64, u64, u32, *const u8) -> u64,
    pub convert_pointer: extern "efiapi" fn(u64, *mut *const u8) -> u64,
    pub get_variable:
        extern "efiapi" fn(*const u16, *const Guid, *mut u32, *mut u64, *mut u8) -> u64,
    pub get_next_variable_name: extern "efiapi" fn(*mut u64, *mut u16, *mut Guid) -> u64,
    pub set_variable: extern "efiapi" fn(*const u16, *const Guid, u32, u64, *const u8) -> u64,
    pub get_next_high_mono_count: extern "efiapi" fn(*mut u32) -> u64,
    pub reset_system: extern "efiapi" fn(u32, u64, u64, *const u8) -> !,
    pub update_capsule: extern "efiapi" fn(*const *const u8, u64, u64) -> u64,
    pub query_capsule_capabilities:
        extern "efiapi" fn(*const *const u8, u64, *mut u64, *mut u32) -> u64,
    pub query_variable_info: extern "efiapi" fn(u32, *mut u64, *mut u64, *mut u64) -> u64,
}

impl RuntimeServices {
    // SAFETY: Caller must ensure ptr points to valid RuntimeServices table
    pub unsafe fn validate(ptr: *const Self) -> Result<(), UefiError> {
        if ptr.is_null() {
            return Err(UefiError::NullPointer {
                context: "runtime_services",
            });
        }

        let header = core::ptr::read_volatile(ptr as *const TableHeader);
        header.verify_signature(RUNTIME_SERVICES_SIGNATURE)?;
        header.verify_crc(ptr as *const u8)?;

        Ok(())
    }
}
