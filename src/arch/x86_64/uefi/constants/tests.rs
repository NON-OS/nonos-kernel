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

use super::signatures::*;
use super::revisions::*;
use super::status;

#[test]
fn test_status_is_error() {
    assert!(!status::is_error(status::EFI_SUCCESS));
    assert!(status::is_error(status::EFI_LOAD_ERROR));
    assert!(status::is_error(status::EFI_NOT_FOUND));
    assert!(status::is_error(status::EFI_SECURITY_VIOLATION));
    assert!(status::is_error(status::EFI_HTTP_ERROR));
}

#[test]
fn test_status_is_success() {
    assert!(status::is_success(status::EFI_SUCCESS));
    assert!(!status::is_success(status::EFI_NOT_FOUND));
}

#[test]
fn test_status_name() {
    assert_eq!(status::name(status::EFI_SUCCESS), "EFI_SUCCESS");
    assert_eq!(status::name(status::EFI_NOT_FOUND), "EFI_NOT_FOUND");
    assert_eq!(status::name(status::EFI_BUFFER_TOO_SMALL), "EFI_BUFFER_TOO_SMALL");
    assert_eq!(status::name(0xFFFF), "EFI_UNKNOWN");
}

#[test]
fn test_status_description() {
    assert_eq!(status::description(status::EFI_SUCCESS), "Operation completed successfully");
    assert_eq!(status::description(status::EFI_NOT_FOUND), "Item was not found");
}

#[test]
fn test_table_signatures() {
    assert_eq!(RUNTIME_SERVICES_SIGNATURE, 0x56524553544E5552);
    assert_eq!(BOOT_SERVICES_SIGNATURE, 0x56524553544F4F42);
}

#[test]
fn test_hash_sizes() {
    assert_eq!(SHA256_HASH_SIZE, 32);
    assert_eq!(SHA384_HASH_SIZE, 48);
    assert_eq!(SHA512_HASH_SIZE, 64);
}

#[test]
fn test_uefi_revisions() {
    assert!(UEFI_REVISION_2_10 > UEFI_REVISION_2_9);
    assert!(UEFI_REVISION_2_9 > UEFI_REVISION_2_8);
    assert!(UEFI_REVISION_2_8 > UEFI_REVISION_2_7);
}

#[test]
fn test_reset_types() {
    assert_eq!(RESET_TYPE_COLD, 0);
    assert_eq!(RESET_TYPE_WARM, 1);
    assert_eq!(RESET_TYPE_SHUTDOWN, 2);
    assert_eq!(RESET_TYPE_PLATFORM_SPECIFIC, 3);
}
