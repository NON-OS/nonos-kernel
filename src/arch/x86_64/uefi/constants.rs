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

/// Runtime Services table signature: "RUNTSERV" in little-endian
pub const RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552;
pub const BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544F4F42;
pub const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

pub const MAX_VARIABLE_NAME_LENGTH: usize = 256;
/// Maximum UEFI variable data size (1MB as per UEFI spec recommendation)
pub const MAX_VARIABLE_DATA_SIZE: usize = 1024 * 1024;

pub const SIGNATURE_LIST_HEADER_SIZE: usize = 28;
pub const SIGNATURE_DATA_HEADER_SIZE: usize = 16;

pub const SHA256_HASH_SIZE: usize = 32;
pub const SHA384_HASH_SIZE: usize = 48;
pub const SHA512_HASH_SIZE: usize = 64;

/// UEFI 2.0 revision
pub const UEFI_REVISION_2_0: u32 = 0x00020000;
/// UEFI 2.1 revision
pub const UEFI_REVISION_2_1: u32 = 0x00020100;
/// UEFI 2.3 revision
pub const UEFI_REVISION_2_3: u32 = 0x00020300;
/// UEFI 2.3.1 revision
pub const UEFI_REVISION_2_3_1: u32 = 0x0002001F;
/// UEFI 2.4 revision
pub const UEFI_REVISION_2_4: u32 = 0x00020400;
/// UEFI 2.5 revision
pub const UEFI_REVISION_2_5: u32 = 0x00020500;
/// UEFI 2.6 revision
pub const UEFI_REVISION_2_6: u32 = 0x00020600;
/// UEFI 2.7 revision
pub const UEFI_REVISION_2_7: u32 = 0x00020700;
/// UEFI 2.8 revision
pub const UEFI_REVISION_2_8: u32 = 0x00020800;
/// UEFI 2.9 revision
pub const UEFI_REVISION_2_9: u32 = 0x00020900;
/// UEFI 2.10 revision
pub const UEFI_REVISION_2_10: u32 = 0x00020A00;

/// Cold reset type value
pub const RESET_TYPE_COLD: u32 = 0;
pub const RESET_TYPE_WARM: u32 = 1;
pub const RESET_TYPE_SHUTDOWN: u32 = 2;
pub const RESET_TYPE_PLATFORM_SPECIFIC: u32 = 3;
pub const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x07FF;
pub const EFI_TIME_ADJUST_DAYLIGHT: u8 = 0x01;
pub const EFI_TIME_IN_DAYLIGHT: u8 = 0x02;

/// EFI Status codes as defined in UEFI Specification
pub mod status {
    pub const EFI_SUCCESS: u64 = 0;
    pub const EFI_LOAD_ERROR: u64 = 1;
    pub const EFI_INVALID_PARAMETER: u64 = 2;
    pub const EFI_UNSUPPORTED: u64 = 3;
    pub const EFI_BAD_BUFFER_SIZE: u64 = 4;
    pub const EFI_BUFFER_TOO_SMALL: u64 = 5;
    pub const EFI_NOT_READY: u64 = 6;
    pub const EFI_DEVICE_ERROR: u64 = 7;
    pub const EFI_WRITE_PROTECTED: u64 = 8;
    pub const EFI_OUT_OF_RESOURCES: u64 = 9;
    pub const EFI_VOLUME_CORRUPTED: u64 = 10;
    pub const EFI_VOLUME_FULL: u64 = 11;
    pub const EFI_NO_MEDIA: u64 = 12;
    pub const EFI_MEDIA_CHANGED: u64 = 13;
    pub const EFI_NOT_FOUND: u64 = 14;
    pub const EFI_ACCESS_DENIED: u64 = 15;
    pub const EFI_NO_RESPONSE: u64 = 16;
    pub const EFI_NO_MAPPING: u64 = 17;
    pub const EFI_TIMEOUT: u64 = 18;
    pub const EFI_NOT_STARTED: u64 = 19;
    pub const EFI_ALREADY_STARTED: u64 = 20;
    pub const EFI_ABORTED: u64 = 21;
    pub const EFI_ICMP_ERROR: u64 = 22;
    pub const EFI_TFTP_ERROR: u64 = 23;
    pub const EFI_PROTOCOL_ERROR: u64 = 24;
    pub const EFI_INCOMPATIBLE_VERSION: u64 = 25;
    pub const EFI_SECURITY_VIOLATION: u64 = 26;
    pub const EFI_CRC_ERROR: u64 = 27;
    pub const EFI_END_OF_MEDIA: u64 = 28;
    pub const EFI_END_OF_FILE: u64 = 31;
    pub const EFI_INVALID_LANGUAGE: u64 = 32;
    pub const EFI_COMPROMISED_DATA: u64 = 33;
    pub const EFI_IP_ADDRESS_CONFLICT: u64 = 34;
    pub const EFI_HTTP_ERROR: u64 = 35;
    pub const EFI_ERROR_BIT: u64 = 1u64 << 63;

    #[inline]
    pub const fn is_error(status: u64) -> bool {
        (status & EFI_ERROR_BIT) != 0 || (status != 0 && status <= 35)
    }

    #[inline]
    pub const fn is_success(status: u64) -> bool {
        status == EFI_SUCCESS
    }

    pub const fn name(status: u64) -> &'static str {
        match status {
            EFI_SUCCESS => "EFI_SUCCESS",
            EFI_LOAD_ERROR => "EFI_LOAD_ERROR",
            EFI_INVALID_PARAMETER => "EFI_INVALID_PARAMETER",
            EFI_UNSUPPORTED => "EFI_UNSUPPORTED",
            EFI_BAD_BUFFER_SIZE => "EFI_BAD_BUFFER_SIZE",
            EFI_BUFFER_TOO_SMALL => "EFI_BUFFER_TOO_SMALL",
            EFI_NOT_READY => "EFI_NOT_READY",
            EFI_DEVICE_ERROR => "EFI_DEVICE_ERROR",
            EFI_WRITE_PROTECTED => "EFI_WRITE_PROTECTED",
            EFI_OUT_OF_RESOURCES => "EFI_OUT_OF_RESOURCES",
            EFI_VOLUME_CORRUPTED => "EFI_VOLUME_CORRUPTED",
            EFI_VOLUME_FULL => "EFI_VOLUME_FULL",
            EFI_NO_MEDIA => "EFI_NO_MEDIA",
            EFI_MEDIA_CHANGED => "EFI_MEDIA_CHANGED",
            EFI_NOT_FOUND => "EFI_NOT_FOUND",
            EFI_ACCESS_DENIED => "EFI_ACCESS_DENIED",
            EFI_NO_RESPONSE => "EFI_NO_RESPONSE",
            EFI_NO_MAPPING => "EFI_NO_MAPPING",
            EFI_TIMEOUT => "EFI_TIMEOUT",
            EFI_NOT_STARTED => "EFI_NOT_STARTED",
            EFI_ALREADY_STARTED => "EFI_ALREADY_STARTED",
            EFI_ABORTED => "EFI_ABORTED",
            EFI_ICMP_ERROR => "EFI_ICMP_ERROR",
            EFI_TFTP_ERROR => "EFI_TFTP_ERROR",
            EFI_PROTOCOL_ERROR => "EFI_PROTOCOL_ERROR",
            EFI_INCOMPATIBLE_VERSION => "EFI_INCOMPATIBLE_VERSION",
            EFI_SECURITY_VIOLATION => "EFI_SECURITY_VIOLATION",
            EFI_CRC_ERROR => "EFI_CRC_ERROR",
            EFI_END_OF_MEDIA => "EFI_END_OF_MEDIA",
            EFI_END_OF_FILE => "EFI_END_OF_FILE",
            EFI_INVALID_LANGUAGE => "EFI_INVALID_LANGUAGE",
            EFI_COMPROMISED_DATA => "EFI_COMPROMISED_DATA",
            EFI_IP_ADDRESS_CONFLICT => "EFI_IP_ADDRESS_CONFLICT",
            EFI_HTTP_ERROR => "EFI_HTTP_ERROR",
            _ => "EFI_UNKNOWN",
        }
    }

    pub const fn description(status: u64) -> &'static str {
        match status {
            EFI_SUCCESS => "Operation completed successfully",
            EFI_LOAD_ERROR => "Image failed to load",
            EFI_INVALID_PARAMETER => "A parameter was incorrect",
            EFI_UNSUPPORTED => "The operation is not supported",
            EFI_BAD_BUFFER_SIZE => "The buffer was not the proper size",
            EFI_BUFFER_TOO_SMALL => "The buffer is not large enough",
            EFI_NOT_READY => "There is no data pending",
            EFI_DEVICE_ERROR => "Physical device reported an error",
            EFI_WRITE_PROTECTED => "The device cannot be written to",
            EFI_OUT_OF_RESOURCES => "A resource has run out",
            EFI_VOLUME_CORRUPTED => "File system inconsistency detected",
            EFI_VOLUME_FULL => "No more space on file system",
            EFI_NO_MEDIA => "No medium in device",
            EFI_MEDIA_CHANGED => "Medium has changed since last access",
            EFI_NOT_FOUND => "Item was not found",
            EFI_ACCESS_DENIED => "Access was denied",
            EFI_NO_RESPONSE => "Server did not respond",
            EFI_NO_MAPPING => "Mapping to device does not exist",
            EFI_TIMEOUT => "Timeout time expired",
            EFI_NOT_STARTED => "Protocol has not been started",
            EFI_ALREADY_STARTED => "Protocol has already been started",
            EFI_ABORTED => "Operation was aborted",
            EFI_ICMP_ERROR => "ICMP error during network operation",
            EFI_TFTP_ERROR => "TFTP error during network operation",
            EFI_PROTOCOL_ERROR => "Protocol error during network operation",
            EFI_INCOMPATIBLE_VERSION => "Incompatible internal version",
            EFI_SECURITY_VIOLATION => "Security violation",
            EFI_CRC_ERROR => "CRC error was detected",
            EFI_END_OF_MEDIA => "Beginning or end of media reached",
            EFI_END_OF_FILE => "End of file reached",
            EFI_INVALID_LANGUAGE => "Invalid language specified",
            EFI_COMPROMISED_DATA => "Security status unknown or compromised",
            EFI_IP_ADDRESS_CONFLICT => "Address conflict during allocation",
            EFI_HTTP_ERROR => "HTTP error during network operation",
            _ => "Unknown error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
