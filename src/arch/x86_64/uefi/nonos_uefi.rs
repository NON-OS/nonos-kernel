// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//!
//! NØNOS UEFI (Unified Extensible Firmware Interface) 
//!
//! # Architecture
//!     +------------------+     +------------------+     +------------------+
//!     |   NØNOS Kernel   | --> |  UefiManager     | --> | RuntimeServices  |
//!     |                  |     |  (Thread-safe)   |     | (UEFI Firmware)  |
//!     +------------------+     +------------------+     +------------------+
//!                                      |
//!                                      v
//!                             +------------------+
//!                             | Variables Cache  |
//!                             | (RwLock<BTree>)  |
//!                             +------------------+
//!                                      |
//!             +------------------------+------------------------+
//!             |                        |                        |
//!             v                        v                        v
//!     +---------------+       +---------------+       +------------------+
//!     | SecureBoot    |       | PK/KEK        |       | db/dbx           |
//!     | SetupMode     |       | Keys          |       | Signature DBs    |
//!     +---------------+       +---------------+       +------------------+
//!
//! # EFI_SIGNATURE_LIST Structure
//!
//!     Offset  Size    Field
//!     +------+-------+----------------------------------------+
//!     | 0    | 16    | SignatureType (GUID)                   |
//!     | 16   | 4     | SignatureListSize (total bytes)        |
//!     | 20   | 4     | SignatureHeaderSize                    |
//!     | 24   | 4     | SignatureSize (each entry size)        |
//!     | 28   | var   | SignatureHeader (optional)             |
//!     | var  | var   | Signatures[0..n] (EFI_SIGNATURE_DATA)  |
//!     +------+-------+----------------------------------------+
//!
//!     EFI_SIGNATURE_DATA:
//!     +------+-------+----------------------------------------+
//!     | 0    | 16    | SignatureOwner (GUID)                  |
//!     | 16   | var   | SignatureData (hash/cert)              |
//!     +------+-------+----------------------------------------+

extern crate alloc;

use alloc::{vec, vec::Vec, string::String, collections::BTreeMap};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::ptr;
use spin::RwLock;

// ============================================================================
// EFI Status Codes
// ============================================================================

/// EFI Status codes
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

    /// Check if status indicates error (high bit set)
    pub const fn is_error(status: u64) -> bool {
        (status & (1u64 << 63)) != 0 || (status != 0 && status <= 32)
    }

    /// Get human-readable status name
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
            EFI_NOT_FOUND => "EFI_NOT_FOUND",
            EFI_ACCESS_DENIED => "EFI_ACCESS_DENIED",
            EFI_SECURITY_VIOLATION => "EFI_SECURITY_VIOLATION",
            _ => "EFI_UNKNOWN",
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// UEFI errors with context
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UefiError {
    /// UEFI not initialized
    NotInitialized,
    /// Already initialized
    AlreadyInitialized,
    /// Runtime services not available
    RuntimeServicesNotAvailable,
    /// Variable not found
    VariableNotFound { name: &'static str },
    /// Variable write failed with EFI status
    VariableWriteFailed { status: u64 },
    /// Variable read failed with EFI status
    VariableReadFailed { status: u64 },
    /// Invalid runtime services signature
    InvalidSignature { expected: u64, found: u64 },
    /// CRC32 verification failed
    CrcMismatch { expected: u32, computed: u32 },
    /// Secure Boot validation failed
    SecureBootFailed,
    /// Not in setup mode
    NotInSetupMode,
    /// Invalid GUID
    InvalidGuid,
    /// Buffer too small
    BufferTooSmall { required: usize, provided: usize },
    /// Access denied
    AccessDenied,
    /// Write protected
    WriteProtected,
    /// Security violation
    SecurityViolation,
    /// Out of resources
    OutOfResources,
    /// Invalid parameter
    InvalidParameter { param: &'static str },
    /// Signature list parse error
    SignatureListParseError { offset: usize },
    /// Hash not found in database
    HashNotInDatabase,
    /// Hash is revoked
    HashRevoked,
}

impl UefiError {
    /// Get human-readable error message
    pub const fn as_str(&self) -> &'static str {
        match self {
            UefiError::NotInitialized => "UEFI not initialized",
            UefiError::AlreadyInitialized => "UEFI already initialized",
            UefiError::RuntimeServicesNotAvailable => "UEFI runtime services not available",
            UefiError::VariableNotFound { .. } => "UEFI variable not found",
            UefiError::VariableWriteFailed { .. } => "UEFI variable write failed",
            UefiError::VariableReadFailed { .. } => "UEFI variable read failed",
            UefiError::InvalidSignature { .. } => "Invalid runtime services signature",
            UefiError::CrcMismatch { .. } => "Table CRC32 verification failed",
            UefiError::SecureBootFailed => "Secure Boot validation failed",
            UefiError::NotInSetupMode => "Not in UEFI Setup Mode",
            UefiError::InvalidGuid => "Invalid GUID format",
            UefiError::BufferTooSmall { .. } => "Buffer too small for data",
            UefiError::AccessDenied => "Access denied to UEFI variable",
            UefiError::WriteProtected => "Variable is write protected",
            UefiError::SecurityViolation => "Security violation",
            UefiError::OutOfResources => "Out of resources",
            UefiError::InvalidParameter { .. } => "Invalid parameter",
            UefiError::SignatureListParseError { .. } => "Failed to parse signature list",
            UefiError::HashNotInDatabase => "Hash not found in signature database",
            UefiError::HashRevoked => "Hash found in revocation database",
        }
    }

    /// Convert EFI status to error
    pub fn from_efi_status(status: u64) -> Option<Self> {
        match status {
            status::EFI_SUCCESS => None,
            status::EFI_NOT_FOUND => Some(UefiError::VariableNotFound { name: "unknown" }),
            status::EFI_ACCESS_DENIED => Some(UefiError::AccessDenied),
            status::EFI_WRITE_PROTECTED => Some(UefiError::WriteProtected),
            status::EFI_SECURITY_VIOLATION => Some(UefiError::SecurityViolation),
            status::EFI_OUT_OF_RESOURCES => Some(UefiError::OutOfResources),
            status::EFI_INVALID_PARAMETER => Some(UefiError::InvalidParameter { param: "unknown" }),
            _ => Some(UefiError::VariableReadFailed { status }),
        }
    }
}

// ============================================================================
// GUID Definition
// ============================================================================

/// UEFI GUID (Globally Unique Identifier)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Create new GUID from components
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self { data1, data2, data3, data4 }
    }

    /// EFI Global Variable GUID
    pub const GLOBAL_VARIABLE: Guid = Guid {
        data1: 0x8be4df61,
        data2: 0x93ca,
        data3: 0x11d2,
        data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    };

    /// Image Security Database GUID (for db, dbx, dbt, dbr)
    pub const IMAGE_SECURITY_DATABASE: Guid = Guid {
        data1: 0xd719b2cb,
        data2: 0x3d3a,
        data3: 0x4596,
        data4: [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    };

    /// EFI_CERT_SHA256_GUID - SHA256 hash signature type
    pub const CERT_SHA256: Guid = Guid {
        data1: 0xc1c41626,
        data2: 0x504c,
        data3: 0x4092,
        data4: [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
    };

    /// EFI_CERT_SHA384_GUID
    pub const CERT_SHA384: Guid = Guid {
        data1: 0xff3e5307,
        data2: 0x9fd0,
        data3: 0x48c9,
        data4: [0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01],
    };

    /// EFI_CERT_SHA512_GUID
    pub const CERT_SHA512: Guid = Guid {
        data1: 0x093e0fae,
        data2: 0xa6c4,
        data3: 0x4f50,
        data4: [0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a],
    };

    /// EFI_CERT_X509_GUID
    pub const CERT_X509: Guid = Guid {
        data1: 0xa5c059a1,
        data2: 0x94e4,
        data3: 0x4aa7,
        data4: [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
    };

    /// EFI_CERT_X509_SHA256_GUID
    pub const CERT_X509_SHA256: Guid = Guid {
        data1: 0x3bd2a492,
        data2: 0x96c0,
        data3: 0x4079,
        data4: [0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed],
    };

    /// Convert to 16-byte array
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    /// Parse from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        Some(Self {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [bytes[8], bytes[9], bytes[10], bytes[11],
                    bytes[12], bytes[13], bytes[14], bytes[15]],
        })
    }

    /// Get hash size for this signature type GUID
    pub fn hash_size(&self) -> Option<usize> {
        if *self == Self::CERT_SHA256 {
            Some(32)
        } else if *self == Self::CERT_SHA384 {
            Some(48)
        } else if *self == Self::CERT_SHA512 {
            Some(64)
        } else {
            None
        }
    }
}

// ============================================================================
// Variable Attributes
// ============================================================================

/// UEFI Variable Attributes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VariableAttributes(u32);

impl VariableAttributes {
    pub const NONE: Self = Self(0);
    pub const NON_VOLATILE: Self = Self(0x00000001);
    pub const BOOTSERVICE_ACCESS: Self = Self(0x00000002);
    pub const RUNTIME_ACCESS: Self = Self(0x00000004);
    pub const HARDWARE_ERROR_RECORD: Self = Self(0x00000008);
    pub const AUTHENTICATED_WRITE_ACCESS: Self = Self(0x00000010);
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: Self = Self(0x00000020);
    pub const APPEND_WRITE: Self = Self(0x00000040);
    pub const ENHANCED_AUTHENTICATED_ACCESS: Self = Self(0x00000080);

    /// Standard persistent variable attributes
    pub const DEFAULT_NV_BS_RT: Self = Self(
        Self::NON_VOLATILE.0 | Self::BOOTSERVICE_ACCESS.0 | Self::RUNTIME_ACCESS.0
    );

    pub const fn empty() -> Self { Self(0) }
    pub const fn bits(&self) -> u32 { self.0 }
    pub const fn from_bits(bits: u32) -> Self { Self(bits) }
    pub const fn contains(&self, other: Self) -> bool { (self.0 & other.0) == other.0 }
    pub const fn is_empty(&self) -> bool { self.0 == 0 }
}

impl core::ops::BitOr for VariableAttributes {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { Self(self.0 | rhs.0) }
}

impl core::ops::BitOrAssign for VariableAttributes {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}

impl core::ops::BitAnd for VariableAttributes {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self(self.0 & rhs.0) }
}

// ============================================================================
// CRC32 Implementation
// ============================================================================

/// CRC32 for UEFI table verification
mod crc32 {
    const CRC32_TABLE: [u32; 256] = generate_table();

    const fn generate_table() -> [u32; 256] {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut crc = i as u32;
            let mut j = 0;
            while j < 8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
                j += 1;
            }
            table[i] = crc;
            i += 1;
        }
        table
    }

    pub fn compute(data: &[u8]) -> u32 {
        let mut crc = 0xFFFFFFFFu32;
        for &byte in data {
            let index = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[index];
        }
        !crc
    }

    pub fn compute_with_zero_crc(data: &[u8], crc_offset: usize) -> u32 {
        let mut crc = 0xFFFFFFFFu32;
        for (i, &byte) in data.iter().enumerate() {
            // Zero out bytes at CRC field position
            let byte = if i >= crc_offset && i < crc_offset + 4 { 0 } else { byte };
            let index = ((crc ^ byte as u32) & 0xFF) as usize;
            crc = (crc >> 8) ^ CRC32_TABLE[index];
        }
        !crc
    }
}

// ============================================================================
// Runtime Services Table
// ============================================================================

const RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552; // "RUNTSERV"

/// UEFI Table Header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

/// UEFI Runtime Services Table
#[repr(C)]
pub struct RuntimeServices {
    pub header: TableHeader,
    pub get_time: extern "efiapi" fn(*mut EfiTime, *mut EfiTimeCapabilities) -> u64,
    pub set_time: extern "efiapi" fn(*const EfiTime) -> u64,
    pub get_wakeup_time: extern "efiapi" fn(*mut u8, *mut u8, *mut EfiTime) -> u64,
    pub set_wakeup_time: extern "efiapi" fn(u8, *const EfiTime) -> u64,
    pub set_virtual_address_map: extern "efiapi" fn(u64, u64, u32, *const u8) -> u64,
    pub convert_pointer: extern "efiapi" fn(u64, *mut *const u8) -> u64,
    pub get_variable: extern "efiapi" fn(*const u16, *const Guid, *mut u32, *mut u64, *mut u8) -> u64,
    pub get_next_variable_name: extern "efiapi" fn(*mut u64, *mut u16, *mut Guid) -> u64,
    pub set_variable: extern "efiapi" fn(*const u16, *const Guid, u32, u64, *const u8) -> u64,
    pub get_next_high_mono_count: extern "efiapi" fn(*mut u32) -> u64,
    pub reset_system: extern "efiapi" fn(u32, u64, u64, *const u8) -> !,
    pub update_capsule: extern "efiapi" fn(*const *const u8, u64, u64) -> u64,
    pub query_capsule_capabilities: extern "efiapi" fn(*const *const u8, u64, *mut u64, *mut u32) -> u64,
    pub query_variable_info: extern "efiapi" fn(u32, *mut u64, *mut u64, *mut u64) -> u64,
}

/// UEFI Time Structure
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

/// UEFI Time Capabilities
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EfiTimeCapabilities {
    pub resolution: u32,
    pub accuracy: u32,
    pub sets_to_zero: u8,
}

// ============================================================================
// Signature List Parsing
// ============================================================================

/// Parsed signature entry from EFI_SIGNATURE_DATA
#[derive(Debug, Clone)]
pub struct SignatureEntry {
    pub owner: Guid,
    pub data: Vec<u8>,
}

/// Parsed signature list from EFI_SIGNATURE_LIST
#[derive(Debug, Clone)]
pub struct SignatureList {
    pub signature_type: Guid,
    pub entries: Vec<SignatureEntry>,
}

/// Parse EFI_SIGNATURE_LIST structures from database variable
pub fn parse_signature_lists(data: &[u8]) -> Result<Vec<SignatureList>, UefiError> {
    let mut lists = Vec::new();
    let mut offset = 0;

    while offset + 28 <= data.len() {
        // Parse EFI_SIGNATURE_LIST header
        let sig_type = Guid::from_bytes(&data[offset..])
            .ok_or(UefiError::SignatureListParseError { offset })?;

        let list_size = u32::from_le_bytes([
            data[offset + 16], data[offset + 17],
            data[offset + 18], data[offset + 19]
        ]) as usize;

        let header_size = u32::from_le_bytes([
            data[offset + 20], data[offset + 21],
            data[offset + 22], data[offset + 23]
        ]) as usize;

        let sig_size = u32::from_le_bytes([
            data[offset + 24], data[offset + 25],
            data[offset + 26], data[offset + 27]
        ]) as usize;

        if list_size == 0 || sig_size < 16 {
            return Err(UefiError::SignatureListParseError { offset });
        }

        // Validate list doesn't exceed data
        if offset + list_size > data.len() {
            return Err(UefiError::SignatureListParseError { offset });
        }

        // Parse signature entries
        let mut entries = Vec::new();
        let entries_start = offset + 28 + header_size;
        let entries_size = list_size - 28 - header_size;

        if entries_size > 0 && sig_size > 16 {
            let num_entries = entries_size / sig_size;
            for i in 0..num_entries {
                let entry_offset = entries_start + i * sig_size;
                if entry_offset + sig_size > data.len() {
                    break;
                }

                let owner = Guid::from_bytes(&data[entry_offset..])
                    .ok_or(UefiError::SignatureListParseError { offset: entry_offset })?;

                let sig_data = data[entry_offset + 16..entry_offset + sig_size].to_vec();

                entries.push(SignatureEntry {
                    owner,
                    data: sig_data,
                });
            }
        }

        lists.push(SignatureList {
            signature_type: sig_type,
            entries,
        });

        offset += list_size;
    }

    Ok(lists)
}

/// Check if hash exists in parsed signature lists
pub fn hash_in_signature_lists(hash: &[u8], lists: &[SignatureList]) -> bool {
    for list in lists {
        // Check if this list type matches our hash size
        let expected_size = list.signature_type.hash_size();
        if let Some(size) = expected_size {
            if hash.len() != size {
                continue;
            }
        }

        // Check each entry
        for entry in &list.entries {
            if entry.data == hash {
                return true;
            }
        }
    }
    false
}

/// Build EFI_SIGNATURE_LIST for appending a hash
pub fn build_signature_list(signature_type: &Guid, owner: &Guid, hash: &[u8]) -> Vec<u8> {
    let sig_size = 16 + hash.len(); // GUID + hash
    let list_size = 28 + sig_size;  // header + one signature

    let mut data = Vec::with_capacity(list_size);

    // SignatureType GUID
    data.extend_from_slice(&signature_type.to_bytes());

    // SignatureListSize
    data.extend_from_slice(&(list_size as u32).to_le_bytes());

    // SignatureHeaderSize (0 for hash types)
    data.extend_from_slice(&0u32.to_le_bytes());

    // SignatureSize
    data.extend_from_slice(&(sig_size as u32).to_le_bytes());

    // EFI_SIGNATURE_DATA: Owner GUID + hash
    data.extend_from_slice(&owner.to_bytes());
    data.extend_from_slice(hash);

    data
}

// ============================================================================
// Variable and Firmware Info
// ============================================================================

/// UEFI Variable
#[derive(Debug, Clone)]
pub struct UefiVariable {
    pub name: String,
    pub guid: Guid,
    pub attributes: VariableAttributes,
    pub data: Vec<u8>,
}

/// Firmware Information
#[derive(Debug, Clone)]
pub struct FirmwareInfo {
    pub vendor: String,
    pub version: String,
    pub revision: u32,
    pub firmware_revision: u32,
    pub secure_boot_enabled: bool,
    pub setup_mode: bool,
    pub variable_support: bool,
    pub runtime_services_supported: bool,
}

impl Default for FirmwareInfo {
    fn default() -> Self {
        Self {
            vendor: String::from("Unknown"),
            version: String::from("0.0"),
            revision: 0,
            firmware_revision: 0,
            secure_boot_enabled: false,
            setup_mode: true,
            variable_support: false,
            runtime_services_supported: false,
        }
    }
}

/// Reset type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResetType {
    Cold = 0,
    Warm = 1,
    Shutdown = 2,
    PlatformSpecific = 3,
}

// ============================================================================
// Statistics
// ============================================================================

/// UEFI Statistics
#[derive(Debug, Clone)]
pub struct UefiStats {
    pub total_variables: u64,
    pub variable_reads: u64,
    pub variable_writes: u64,
    pub variable_read_errors: u64,
    pub variable_write_errors: u64,
    pub secure_boot_enabled: bool,
    pub setup_mode: bool,
    pub runtime_services_available: bool,
}

struct InternalStats {
    variable_reads: AtomicU64,
    variable_writes: AtomicU64,
    variable_read_errors: AtomicU64,
    variable_write_errors: AtomicU64,
}

impl InternalStats {
    const fn new() -> Self {
        Self {
            variable_reads: AtomicU64::new(0),
            variable_writes: AtomicU64::new(0),
            variable_read_errors: AtomicU64::new(0),
            variable_write_errors: AtomicU64::new(0),
        }
    }
}

// ============================================================================
// UEFI Manager
// ============================================================================

/// NØNOS owner GUID for signatures we add
const NONOS_OWNER_GUID: Guid = Guid {
    data1: 0x4E4F4E4F, // "NONO"
    data2: 0x534F,     // "SO"
    data3: 0x5345,     // "SE"
    data4: [0x43, 0x55, 0x52, 0x49, 0x54, 0x59, 0x00, 0x00], // "CURITY\0\0"
};

/// Thread-safe UEFI Manager
pub struct UefiManager {
    runtime_services: RwLock<Option<*const RuntimeServices>>,
    firmware_info: RwLock<FirmwareInfo>,
    variables_cache: RwLock<BTreeMap<(String, Guid), UefiVariable>>,
    stats: InternalStats,
}

unsafe impl Send for UefiManager {}
unsafe impl Sync for UefiManager {}

impl UefiManager {
    pub const fn new() -> Self {
        Self {
            runtime_services: RwLock::new(None),
            firmware_info: RwLock::new(FirmwareInfo {
                vendor: String::new(),
                version: String::new(),
                revision: 0,
                firmware_revision: 0,
                secure_boot_enabled: false,
                setup_mode: true,
                variable_support: false,
                runtime_services_supported: false,
            }),
            variables_cache: RwLock::new(BTreeMap::new()),
            stats: InternalStats::new(),
        }
    }

    /// Initialize UEFI services
    pub fn init(&self, runtime_services_addr: Option<u64>) -> Result<(), UefiError> {
        if INITIALIZED.load(Ordering::SeqCst) {
            return Err(UefiError::AlreadyInitialized);
        }

        if let Some(addr) = runtime_services_addr {
            if addr != 0 {
                let rt_ptr = addr as *const RuntimeServices;

                // Verify signature and CRC
                self.verify_table(rt_ptr)?;

                *self.runtime_services.write() = Some(rt_ptr);
            }
        }

        // Detect and cache firmware info
        self.detect_firmware_info();

        // Cache security-critical variables
        self.cache_security_variables();

        INITIALIZED.store(true, Ordering::SeqCst);
        crate::log_info!("UEFI integration initialized");

        Ok(())
    }

    /// Verify runtime services table signature and CRC
    fn verify_table(&self, rt_ptr: *const RuntimeServices) -> Result<(), UefiError> {
        if rt_ptr.is_null() {
            return Err(UefiError::RuntimeServicesNotAvailable);
        }

        unsafe {
            let header = ptr::read_volatile(rt_ptr as *const TableHeader);

            // Check signature
            if header.signature != RUNTIME_SERVICES_SIGNATURE {
                return Err(UefiError::InvalidSignature {
                    expected: RUNTIME_SERVICES_SIGNATURE,
                    found: header.signature,
                });
            }

            // Verify CRC32
            let header_size = header.header_size as usize;
            if header_size >= 24 {
                let header_bytes = core::slice::from_raw_parts(
                    rt_ptr as *const u8,
                    header_size
                );
                let computed_crc = crc32::compute_with_zero_crc(header_bytes, 16);

                if computed_crc != header.crc32 {
                    return Err(UefiError::CrcMismatch {
                        expected: header.crc32,
                        computed: computed_crc,
                    });
                }
            }
        }

        Ok(())
    }

    /// Detect firmware info by reading UEFI variables
    fn detect_firmware_info(&self) {
        let mut info = FirmwareInfo::default();

        let has_rt = self.runtime_services.read().is_some();
        info.runtime_services_supported = has_rt;
        info.variable_support = has_rt;

        // Read SecureBoot variable (1 byte: 0=disabled, 1=enabled)
        if let Ok(var) = self.read_variable_raw("SecureBoot", &Guid::GLOBAL_VARIABLE) {
            info.secure_boot_enabled = !var.is_empty() && var[0] == 1;
        }

        // Read SetupMode variable (1 byte: 0=user mode, 1=setup mode)
        if let Ok(var) = self.read_variable_raw("SetupMode", &Guid::GLOBAL_VARIABLE) {
            info.setup_mode = !var.is_empty() && var[0] == 1;
        }

        info.vendor = String::from("NONOS UEFI");
        info.version = String::from("2.8");
        info.revision = 0x00020008;
        info.firmware_revision = 0x00010000;

        *self.firmware_info.write() = info;
    }

    /// Cache security-critical variables
    fn cache_security_variables(&self) {
        let vars = [
            ("SecureBoot", Guid::GLOBAL_VARIABLE),
            ("SetupMode", Guid::GLOBAL_VARIABLE),
            ("PK", Guid::GLOBAL_VARIABLE),
            ("KEK", Guid::GLOBAL_VARIABLE),
            ("db", Guid::IMAGE_SECURITY_DATABASE),
            ("dbx", Guid::IMAGE_SECURITY_DATABASE),
        ];

        for (name, guid) in &vars {
            if let Ok(data) = self.read_variable_raw(name, guid) {
                let var = UefiVariable {
                    name: String::from(*name),
                    guid: *guid,
                    attributes: VariableAttributes::DEFAULT_NV_BS_RT,
                    data,
                };
                self.variables_cache.write().insert((String::from(*name), *guid), var);
            }
        }
    }

    /// Read variable directly from firmware (no cache)
    fn read_variable_raw(&self, name: &str, guid: &Guid) -> Result<Vec<u8>, UefiError> {
        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        // Convert name to UCS-2 null-terminated
        let mut name_buf: [u16; 256] = [0; 256];
        for (i, ch) in name.chars().enumerate() {
            if i >= 255 { break; }
            name_buf[i] = ch as u16;
        }

        let mut data_size: u64 = 0;
        let mut attributes: u32 = 0;

        // First call to get required size
        let status = unsafe {
            let get_variable = (*rt_ptr).get_variable;
            get_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                &mut attributes,
                &mut data_size,
                ptr::null_mut(),
            )
        };

        // EFI_BUFFER_TOO_SMALL is expected
        if status != status::EFI_BUFFER_TOO_SMALL && status != status::EFI_SUCCESS {
            if status == status::EFI_NOT_FOUND {
                return Err(UefiError::VariableNotFound { name: "variable" });
            }
            return Err(UefiError::VariableReadFailed { status });
        }

        if data_size == 0 {
            return Ok(Vec::new());
        }

        // Allocate buffer and read
        let mut data = vec![0u8; data_size as usize];
        let status = unsafe {
            let get_variable = (*rt_ptr).get_variable;
            get_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                &mut attributes,
                &mut data_size,
                data.as_mut_ptr(),
            )
        };

        if status != status::EFI_SUCCESS {
            return Err(UefiError::VariableReadFailed { status });
        }

        data.truncate(data_size as usize);
        Ok(data)
    }

    /// Get variable (uses cache, falls back to firmware)
    pub fn get_variable(&self, name: &str, guid: &Guid) -> Result<UefiVariable, UefiError> {
        self.stats.variable_reads.fetch_add(1, Ordering::Relaxed);

        // Check cache first
        {
            let cache = self.variables_cache.read();
            if let Some(var) = cache.get(&(String::from(name), *guid)) {
                return Ok(var.clone());
            }
        }

        // Read from firmware
        match self.read_variable_raw(name, guid) {
            Ok(data) => {
                let var = UefiVariable {
                    name: String::from(name),
                    guid: *guid,
                    attributes: VariableAttributes::DEFAULT_NV_BS_RT,
                    data,
                };

                // Update cache
                self.variables_cache.write().insert((String::from(name), *guid), var.clone());
                Ok(var)
            }
            Err(e) => {
                self.stats.variable_read_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Set variable
    pub fn set_variable(
        &self,
        name: &str,
        guid: &Guid,
        attributes: VariableAttributes,
        data: &[u8],
    ) -> Result<(), UefiError> {
        self.stats.variable_writes.fetch_add(1, Ordering::Relaxed);

        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        // Convert name to UCS-2
        let mut name_buf: [u16; 256] = [0; 256];
        for (i, ch) in name.chars().enumerate() {
            if i >= 255 { break; }
            name_buf[i] = ch as u16;
        }

        let status = unsafe {
            let set_variable = (*rt_ptr).set_variable;
            set_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                attributes.bits(),
                data.len() as u64,
                data.as_ptr(),
            )
        };

        if status != status::EFI_SUCCESS {
            self.stats.variable_write_errors.fetch_add(1, Ordering::Relaxed);
            return Err(UefiError::VariableWriteFailed { status });
        }

        // Update cache
        let var = UefiVariable {
            name: String::from(name),
            guid: *guid,
            attributes,
            data: data.to_vec(),
        };
        self.variables_cache.write().insert((String::from(name), *guid), var);

        Ok(())
    }

    /// Append to variable (for signature databases)
    pub fn append_variable(
        &self,
        name: &str,
        guid: &Guid,
        data: &[u8],
    ) -> Result<(), UefiError> {
        self.stats.variable_writes.fetch_add(1, Ordering::Relaxed);

        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        let mut name_buf: [u16; 256] = [0; 256];
        for (i, ch) in name.chars().enumerate() {
            if i >= 255 { break; }
            name_buf[i] = ch as u16;
        }

        // Use APPEND_WRITE attribute
        let attrs = VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS
            | VariableAttributes::APPEND_WRITE;

        let status = unsafe {
            let set_variable = (*rt_ptr).set_variable;
            set_variable(
                name_buf.as_ptr(),
                guid as *const Guid,
                attrs.bits(),
                data.len() as u64,
                data.as_ptr(),
            )
        };

        if status != status::EFI_SUCCESS {
            self.stats.variable_write_errors.fetch_add(1, Ordering::Relaxed);
            return Err(UefiError::VariableWriteFailed { status });
        }

        // Invalidate cache for this variable
        self.variables_cache.write().remove(&(String::from(name), *guid));

        Ok(())
    }

    /// Get firmware information
    pub fn get_firmware_info(&self) -> FirmwareInfo {
        self.firmware_info.read().clone()
    }

    /// Check if Secure Boot is enabled
    pub fn is_secure_boot_enabled(&self) -> bool {
        self.firmware_info.read().secure_boot_enabled
    }

    /// Check if in Setup Mode
    pub fn is_setup_mode(&self) -> bool {
        if let Ok(var) = self.get_variable("SetupMode", &Guid::GLOBAL_VARIABLE) {
            !var.data.is_empty() && var.data[0] == 1
        } else {
            false
        }
    }

    /// Get signature database (db)
    pub fn get_signature_database(&self) -> Result<Vec<SignatureList>, UefiError> {
        let var = self.get_variable("db", &Guid::IMAGE_SECURITY_DATABASE)?;
        parse_signature_lists(&var.data)
    }

    /// Get revoked signature database (dbx)
    pub fn get_revoked_database(&self) -> Result<Vec<SignatureList>, UefiError> {
        let var = self.get_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE)?;
        parse_signature_lists(&var.data)
    }

    /// Verify hash against Secure Boot databases
    pub fn verify_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_secure_boot_enabled() {
            // Secure Boot disabled, allow all
            return Ok(());
        }

        // Check if hash is revoked (dbx)
        if let Ok(dbx_lists) = self.get_revoked_database() {
            if hash_in_signature_lists(hash, &dbx_lists) {
                return Err(UefiError::HashRevoked);
            }
        }

        // Check if hash is authorized (db)
        if let Ok(db_lists) = self.get_signature_database() {
            if hash_in_signature_lists(hash, &db_lists) {
                return Ok(());
            }
        }

        Err(UefiError::HashNotInDatabase)
    }

    /// Add hash to authorized database (db) - requires Setup Mode
    pub fn authorize_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_setup_mode() {
            return Err(UefiError::NotInSetupMode);
        }

        // Determine signature type from hash length
        let sig_type = match hash.len() {
            32 => Guid::CERT_SHA256,
            48 => Guid::CERT_SHA384,
            64 => Guid::CERT_SHA512,
            _ => return Err(UefiError::InvalidParameter { param: "hash length" }),
        };

        // Build signature list
        let sig_list = build_signature_list(&sig_type, &NONOS_OWNER_GUID, hash);

        // Append to db
        self.append_variable("db", &Guid::IMAGE_SECURITY_DATABASE, &sig_list)?;

        crate::log_info!("Hash authorized in Secure Boot database");
        Ok(())
    }

    /// Add hash to revoked database (dbx) - requires Setup Mode
    pub fn revoke_hash(&self, hash: &[u8]) -> Result<(), UefiError> {
        if !self.is_setup_mode() {
            return Err(UefiError::NotInSetupMode);
        }

        let sig_type = match hash.len() {
            32 => Guid::CERT_SHA256,
            48 => Guid::CERT_SHA384,
            64 => Guid::CERT_SHA512,
            _ => return Err(UefiError::InvalidParameter { param: "hash length" }),
        };

        let sig_list = build_signature_list(&sig_type, &NONOS_OWNER_GUID, hash);

        self.append_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE, &sig_list)?;

        crate::log_info!("Hash added to Secure Boot revocation database");
        Ok(())
    }

    /// Get UEFI time
    pub fn get_time(&self) -> Result<EfiTime, UefiError> {
        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        let mut time = EfiTime::default();
        let mut capabilities = EfiTimeCapabilities::default();

        let status = unsafe {
            let get_time = (*rt_ptr).get_time;
            get_time(&mut time, &mut capabilities)
        };

        if status != status::EFI_SUCCESS {
            return Err(UefiError::from_efi_status(status)
                .unwrap_or(UefiError::VariableReadFailed { status }));
        }

        Ok(time)
    }

    /// Reset system
    pub fn reset_system(&self, reset_type: ResetType) -> Result<(), UefiError> {
        let rt_guard = self.runtime_services.read();
        let rt_ptr = (*rt_guard).ok_or(UefiError::RuntimeServicesNotAvailable)?;

        crate::log_info!("UEFI system reset: {:?}", reset_type);

        unsafe {
            let reset_system = (*rt_ptr).reset_system;
            reset_system(reset_type as u32, 0, 0, ptr::null());
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> UefiStats {
        let cache = self.variables_cache.read();
        let info = self.firmware_info.read();

        UefiStats {
            total_variables: cache.len() as u64,
            variable_reads: self.stats.variable_reads.load(Ordering::Relaxed),
            variable_writes: self.stats.variable_writes.load(Ordering::Relaxed),
            variable_read_errors: self.stats.variable_read_errors.load(Ordering::Relaxed),
            variable_write_errors: self.stats.variable_write_errors.load(Ordering::Relaxed),
            secure_boot_enabled: info.secure_boot_enabled,
            setup_mode: info.setup_mode,
            runtime_services_available: info.runtime_services_supported,
        }
    }
}

// ============================================================================
// Global State
// ============================================================================

static INITIALIZED: AtomicBool = AtomicBool::new(false);
static UEFI_MANAGER: UefiManager = UefiManager::new();

// ============================================================================
// Public API
// ============================================================================

/// Initialize UEFI integration
pub fn init(runtime_services_addr: Option<u64>) -> Result<(), UefiError> {
    UEFI_MANAGER.init(runtime_services_addr)
}

/// Check if initialized
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Get firmware information
pub fn get_firmware_info() -> Option<FirmwareInfo> {
    if !is_initialized() { return None; }
    Some(UEFI_MANAGER.get_firmware_info())
}

/// Get UEFI variable
pub fn get_variable(name: &str, guid: &Guid) -> Option<UefiVariable> {
    UEFI_MANAGER.get_variable(name, guid).ok()
}

/// Set UEFI variable
pub fn set_variable(
    name: &str,
    guid: &Guid,
    attributes: VariableAttributes,
    data: &[u8],
) -> Result<(), UefiError> {
    UEFI_MANAGER.set_variable(name, guid, attributes, data)
}

/// Check if Secure Boot is enabled
pub fn is_secure_boot_enabled() -> bool {
    UEFI_MANAGER.is_secure_boot_enabled()
}

/// Check if in Setup Mode
pub fn is_setup_mode() -> bool {
    UEFI_MANAGER.is_setup_mode()
}

/// Reset system
pub fn reset_system(reset_type: ResetType) -> Result<(), UefiError> {
    UEFI_MANAGER.reset_system(reset_type)
}

/// Get UEFI statistics
pub fn get_uefi_stats() -> UefiStats {
    UEFI_MANAGER.get_stats()
}

/// Verify runtime services integrity
pub fn verify_runtime_services() -> bool {
    let rt_guard = UEFI_MANAGER.runtime_services.read();
    if let Some(rt_ptr) = *rt_guard {
        UEFI_MANAGER.verify_table(rt_ptr).is_ok()
    } else {
        false
    }
}

/// Verify boot services (always true - boot services exited before kernel)
pub fn verify_boot_services() -> bool {
    true
}

// ============================================================================
// Secure Boot Module
// ============================================================================

/// Secure Boot verification and management
pub mod secure_boot {
    use super::*;

    /// Verify binary hash against Secure Boot databases
    pub fn verify_binary(binary_hash: &[u8; 32]) -> bool {
        UEFI_MANAGER.verify_hash(binary_hash).is_ok()
    }

    /// Authorize a hash (add to db) - requires Setup Mode
    pub fn authorize_signature(signature: &[u8; 32]) -> Result<(), UefiError> {
        UEFI_MANAGER.authorize_hash(signature)
    }

    /// Revoke a hash (add to dbx) - requires Setup Mode
    pub fn revoke_signature(signature: &[u8; 32]) -> Result<(), UefiError> {
        UEFI_MANAGER.revoke_hash(signature)
    }

    /// Get Secure Boot status
    pub fn get_status() -> SecureBootStatus {
        let has_pk = UEFI_MANAGER.get_variable("PK", &Guid::GLOBAL_VARIABLE).is_ok();
        let has_kek = UEFI_MANAGER.get_variable("KEK", &Guid::GLOBAL_VARIABLE).is_ok();
        let has_db = UEFI_MANAGER.get_variable("db", &Guid::IMAGE_SECURITY_DATABASE).is_ok();
        let has_dbx = UEFI_MANAGER.get_variable("dbx", &Guid::IMAGE_SECURITY_DATABASE).is_ok();

        SecureBootStatus {
            enabled: is_secure_boot_enabled(),
            setup_mode: is_setup_mode(),
            has_pk,
            has_kek,
            has_db,
            has_dbx,
        }
    }

    /// Secure Boot status
    #[derive(Debug, Clone)]
    pub struct SecureBootStatus {
        pub enabled: bool,
        pub setup_mode: bool,
        pub has_pk: bool,
        pub has_kek: bool,
        pub has_db: bool,
        pub has_dbx: bool,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        assert_eq!(UefiError::NotInitialized.as_str(), "UEFI not initialized");
        assert_eq!(UefiError::HashRevoked.as_str(), "Hash found in revocation database");
        assert_eq!(UefiError::HashNotInDatabase.as_str(), "Hash not found in signature database");
    }

    #[test]
    fn test_status_codes() {
        assert!(!status::is_error(status::EFI_SUCCESS));
        assert!(status::is_error(status::EFI_NOT_FOUND));
        assert_eq!(status::name(status::EFI_SUCCESS), "EFI_SUCCESS");
        assert_eq!(status::name(status::EFI_BUFFER_TOO_SMALL), "EFI_BUFFER_TOO_SMALL");
    }

    #[test]
    fn test_guid_creation() {
        let guid = Guid::GLOBAL_VARIABLE;
        assert_eq!(guid.data1, 0x8be4df61);
        assert_eq!(guid.data2, 0x93ca);
        assert_eq!(guid.data3, 0x11d2);
    }

    #[test]
    fn test_guid_bytes_roundtrip() {
        let guid = Guid::new(0x12345678, 0xABCD, 0xEF01, [0, 1, 2, 3, 4, 5, 6, 7]);
        let bytes = guid.to_bytes();
        let parsed = Guid::from_bytes(&bytes).unwrap();
        assert_eq!(guid, parsed);
    }

    #[test]
    fn test_guid_hash_size() {
        assert_eq!(Guid::CERT_SHA256.hash_size(), Some(32));
        assert_eq!(Guid::CERT_SHA384.hash_size(), Some(48));
        assert_eq!(Guid::CERT_SHA512.hash_size(), Some(64));
        assert_eq!(Guid::GLOBAL_VARIABLE.hash_size(), None);
    }

    #[test]
    fn test_crc32() {
        let data = b"123456789";
        let crc = crc32::compute(data);
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_variable_attributes() {
        let attrs = VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS;
        assert!(attrs.contains(VariableAttributes::NON_VOLATILE));
        assert!(attrs.contains(VariableAttributes::RUNTIME_ACCESS));
        assert!(!attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS));
    }

    #[test]
    fn test_build_signature_list() {
        let hash = [0u8; 32];
        let list = build_signature_list(&Guid::CERT_SHA256, &NONOS_OWNER_GUID, &hash);

        // Header (28) + GUID (16) + hash (32) = 76 bytes
        assert_eq!(list.len(), 76);

        // Verify signature type
        let sig_type = Guid::from_bytes(&list[0..16]).unwrap();
        assert_eq!(sig_type, Guid::CERT_SHA256);

        // Verify list size
        let list_size = u32::from_le_bytes([list[16], list[17], list[18], list[19]]);
        assert_eq!(list_size, 76);
    }

    #[test]
    fn test_parse_signature_list() {
        let hash = [0xAB; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &NONOS_OWNER_GUID, &hash);

        let lists = parse_signature_lists(&list_data).unwrap();
        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].signature_type, Guid::CERT_SHA256);
        assert_eq!(lists[0].entries.len(), 1);
        assert_eq!(lists[0].entries[0].owner, NONOS_OWNER_GUID);
        assert_eq!(lists[0].entries[0].data, hash.to_vec());
    }

    #[test]
    fn test_hash_in_signature_lists() {
        let hash = [0xCD; 32];
        let list_data = build_signature_list(&Guid::CERT_SHA256, &NONOS_OWNER_GUID, &hash);
        let lists = parse_signature_lists(&list_data).unwrap();

        assert!(hash_in_signature_lists(&hash, &lists));
        assert!(!hash_in_signature_lists(&[0xFF; 32], &lists));
    }

    #[test]
    fn test_reset_type_values() {
        assert_eq!(ResetType::Cold as u32, 0);
        assert_eq!(ResetType::Warm as u32, 1);
        assert_eq!(ResetType::Shutdown as u32, 2);
        assert_eq!(ResetType::PlatformSpecific as u32, 3);
    }

    #[test]
    fn test_firmware_info_default() {
        let info = FirmwareInfo::default();
        assert_eq!(info.vendor, "Unknown");
        assert!(!info.secure_boot_enabled);
        assert!(info.setup_mode);
    }
}
