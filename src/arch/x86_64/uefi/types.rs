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

use super::constants::{SHA256_HASH_SIZE, SHA384_HASH_SIZE, SHA512_HASH_SIZE};
use core::fmt;
use core::hash::{Hash, Hasher};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    #[inline]
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    #[inline]
    pub const fn null() -> Self {
        Self {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    #[inline]
    pub const fn is_null(&self) -> bool {
        self.data1 == 0
            && self.data2 == 0
            && self.data3 == 0
            && self.data4[0] == 0
            && self.data4[1] == 0
            && self.data4[2] == 0
            && self.data4[3] == 0
            && self.data4[4] == 0
            && self.data4[5] == 0
            && self.data4[6] == 0
            && self.data4[7] == 0
    }

    pub const GLOBAL_VARIABLE: Guid = Guid {
        data1: 0x8be4df61,
        data2: 0x93ca,
        data3: 0x11d2,
        data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    };

    pub const IMAGE_SECURITY_DATABASE: Guid = Guid {
        data1: 0xd719b2cb,
        data2: 0x3d3a,
        data3: 0x4596,
        data4: [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    };

    pub const CERT_SHA256: Guid = Guid {
        data1: 0xc1c41626,
        data2: 0x504c,
        data3: 0x4092,
        data4: [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
    };

    pub const CERT_SHA384: Guid = Guid {
        data1: 0xff3e5307,
        data2: 0x9fd0,
        data3: 0x48c9,
        data4: [0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01],
    };

    pub const CERT_SHA512: Guid = Guid {
        data1: 0x093e0fae,
        data2: 0xa6c4,
        data3: 0x4f50,
        data4: [0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a],
    };

    pub const CERT_X509: Guid = Guid {
        data1: 0xa5c059a1,
        data2: 0x94e4,
        data3: 0x4aa7,
        data4: [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
    };

    pub const CERT_X509_SHA256: Guid = Guid {
        data1: 0x3bd2a492,
        data2: 0x96c0,
        data3: 0x4079,
        data4: [0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed],
    };

    pub const CERT_X509_SHA384: Guid = Guid {
        data1: 0x7076876e,
        data2: 0x80c2,
        data3: 0x4ee6,
        data4: [0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b],
    };

    pub const CERT_X509_SHA512: Guid = Guid {
        data1: 0x446dbf63,
        data2: 0x2502,
        data3: 0x4cda,
        data4: [0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d],
    };

    pub const NONOS_OWNER: Guid = Guid {
        data1: 0x4E4F4E4F,
        data2: 0x534F,
        data3: 0x5345,
        data4: [0x43, 0x55, 0x52, 0x49, 0x54, 0x59, 0x00, 0x00],
    };

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..4].copy_from_slice(&self.data1.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.data2.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.data3.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.data4);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        Some(Self {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ],
        })
    }

    pub fn hash_size(&self) -> Option<usize> {
        if *self == Self::CERT_SHA256 || *self == Self::CERT_X509_SHA256 {
            Some(SHA256_HASH_SIZE)
        } else if *self == Self::CERT_SHA384 || *self == Self::CERT_X509_SHA384 {
            Some(SHA384_HASH_SIZE)
        } else if *self == Self::CERT_SHA512 || *self == Self::CERT_X509_SHA512 {
            Some(SHA512_HASH_SIZE)
        } else {
            None
        }
    }

    pub const fn is_hash_type(&self) -> bool {
        self.data1 == Self::CERT_SHA256.data1
            || self.data1 == Self::CERT_SHA384.data1
            || self.data1 == Self::CERT_SHA512.data1
    }

    pub const fn is_certificate_type(&self) -> bool {
        self.data1 == Self::CERT_X509.data1
            || self.data1 == Self::CERT_X509_SHA256.data1
            || self.data1 == Self::CERT_X509_SHA384.data1
            || self.data1 == Self::CERT_X509_SHA512.data1
    }
}

impl Hash for Guid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data1.hash(state);
        self.data2.hash(state);
        self.data3.hash(state);
        self.data4.hash(state);
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Guid({:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X})",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl Default for Guid {
    fn default() -> Self {
        Self::null()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
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
    pub const DEFAULT_NV_BS_RT: Self =
        Self(Self::NON_VOLATILE.0 | Self::BOOTSERVICE_ACCESS.0 | Self::RUNTIME_ACCESS.0);

    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & 0xFF)
    }

    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn is_non_volatile(&self) -> bool {
        self.contains(Self::NON_VOLATILE)
    }

    #[inline]
    pub const fn is_runtime_access(&self) -> bool {
        self.contains(Self::RUNTIME_ACCESS)
    }

    #[inline]
    pub const fn requires_authentication(&self) -> bool {
        self.contains(Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
            || self.contains(Self::ENHANCED_AUTHENTICATED_ACCESS)
    }

    #[inline]
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    #[inline]
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    #[inline]
    pub fn toggle(&mut self, other: Self) {
        self.0 ^= other.0;
    }

    #[inline]
    pub fn set(&mut self, other: Self, value: bool) {
        if value {
            self.insert(other);
        } else {
            self.remove(other);
        }
    }

    #[inline]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for VariableAttributes {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for VariableAttributes {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for VariableAttributes {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitAndAssign for VariableAttributes {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl core::ops::BitXor for VariableAttributes {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }
}

impl core::ops::Not for VariableAttributes {
    type Output = Self;
    #[inline]
    fn not(self) -> Self {
        Self(!self.0)
    }
}

impl fmt::Debug for VariableAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_set();
        if self.contains(Self::NON_VOLATILE) {
            list.entry(&"NON_VOLATILE");
        }
        if self.contains(Self::BOOTSERVICE_ACCESS) {
            list.entry(&"BOOTSERVICE_ACCESS");
        }
        if self.contains(Self::RUNTIME_ACCESS) {
            list.entry(&"RUNTIME_ACCESS");
        }
        if self.contains(Self::HARDWARE_ERROR_RECORD) {
            list.entry(&"HARDWARE_ERROR_RECORD");
        }
        if self.contains(Self::AUTHENTICATED_WRITE_ACCESS) {
            list.entry(&"AUTHENTICATED_WRITE_ACCESS");
        }
        if self.contains(Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
            list.entry(&"TIME_BASED_AUTHENTICATED_WRITE_ACCESS");
        }
        if self.contains(Self::APPEND_WRITE) {
            list.entry(&"APPEND_WRITE");
        }
        if self.contains(Self::ENHANCED_AUTHENTICATED_ACCESS) {
            list.entry(&"ENHANCED_AUTHENTICATED_ACCESS");
        }
        list.finish()
    }
}

impl Default for VariableAttributes {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ResetType {
    Cold = 0,
    Warm = 1,
    Shutdown = 2,
    PlatformSpecific = 3,
}

impl ResetType {
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Cold),
            1 => Some(Self::Warm),
            2 => Some(Self::Shutdown),
            3 => Some(Self::PlatformSpecific),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Cold => "Cold",
            Self::Warm => "Warm",
            Self::Shutdown => "Shutdown",
            Self::PlatformSpecific => "PlatformSpecific",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Cold => "Full power cycle reset",
            Self::Warm => "CPU reset without power cycle",
            Self::Shutdown => "System power off",
            Self::PlatformSpecific => "Platform-specific reset",
        }
    }
}

impl Default for ResetType {
    fn default() -> Self {
        Self::Cold
    }
}

impl fmt::Display for ResetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod guid_tests {
        use super::*;

        #[test]
        fn test_guid_creation() {
            let guid = Guid::new(0x12345678, 0xABCD, 0xEF01, [0, 1, 2, 3, 4, 5, 6, 7]);
            assert_eq!(guid.data1, 0x12345678);
            assert_eq!(guid.data2, 0xABCD);
            assert_eq!(guid.data3, 0xEF01);
            assert_eq!(guid.data4, [0, 1, 2, 3, 4, 5, 6, 7]);
        }

        #[test]
        fn test_guid_null() {
            let null = Guid::null();
            assert!(null.is_null());

            let non_null = Guid::GLOBAL_VARIABLE;
            assert!(!non_null.is_null());
        }

        #[test]
        fn test_guid_bytes_roundtrip() {
            let guid = Guid::new(0x12345678, 0xABCD, 0xEF01, [0, 1, 2, 3, 4, 5, 6, 7]);
            let bytes = guid.to_bytes();
            let parsed = Guid::from_bytes(&bytes).unwrap();
            assert_eq!(guid, parsed);
        }

        #[test]
        fn test_guid_from_bytes_too_short() {
            assert!(Guid::from_bytes(&[0; 15]).is_none());
            assert!(Guid::from_bytes(&[]).is_none());
        }

        #[test]
        fn test_guid_hash_size() {
            assert_eq!(Guid::CERT_SHA256.hash_size(), Some(32));
            assert_eq!(Guid::CERT_SHA384.hash_size(), Some(48));
            assert_eq!(Guid::CERT_SHA512.hash_size(), Some(64));
            assert_eq!(Guid::CERT_X509_SHA256.hash_size(), Some(32));
            assert_eq!(Guid::GLOBAL_VARIABLE.hash_size(), None);
        }

        #[test]
        fn test_guid_equality() {
            assert_eq!(Guid::GLOBAL_VARIABLE, Guid::GLOBAL_VARIABLE);
            assert_ne!(Guid::GLOBAL_VARIABLE, Guid::IMAGE_SECURITY_DATABASE);
        }

        #[test]
        fn test_guid_display() {
            let guid = Guid::GLOBAL_VARIABLE;
            let s = format!("{}", guid);
            assert!(s.contains("8be4df61"));
        }

        #[test]
        fn test_guid_debug() {
            let guid = Guid::GLOBAL_VARIABLE;
            let s = format!("{:?}", guid);
            assert!(s.contains("Guid"));
            assert!(s.contains("8BE4DF61"));
        }

        #[test]
        fn test_well_known_guids() {
            assert_eq!(Guid::GLOBAL_VARIABLE.data1, 0x8be4df61);
            assert_eq!(Guid::IMAGE_SECURITY_DATABASE.data1, 0xd719b2cb);
            assert_eq!(Guid::CERT_SHA256.data1, 0xc1c41626);
        }
    }

    mod variable_attributes_tests {
        use super::*;

        #[test]
        fn test_attributes_empty() {
            let attrs = VariableAttributes::empty();
            assert!(attrs.is_empty());
            assert_eq!(attrs.bits(), 0);
        }

        #[test]
        fn test_attributes_bitor() {
            let attrs = VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS;
            assert!(attrs.contains(VariableAttributes::NON_VOLATILE));
            assert!(attrs.contains(VariableAttributes::RUNTIME_ACCESS));
            assert!(!attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS));
        }

        #[test]
        fn test_attributes_default_nv_bs_rt() {
            let attrs = VariableAttributes::DEFAULT_NV_BS_RT;
            assert!(attrs.is_non_volatile());
            assert!(attrs.is_runtime_access());
            assert!(attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS));
        }

        #[test]
        fn test_attributes_insert_remove() {
            let mut attrs = VariableAttributes::empty();
            attrs.insert(VariableAttributes::NON_VOLATILE);
            assert!(attrs.is_non_volatile());

            attrs.remove(VariableAttributes::NON_VOLATILE);
            assert!(!attrs.is_non_volatile());
        }

        #[test]
        fn test_attributes_from_bits() {
            let attrs = VariableAttributes::from_bits(0x07);
            assert!(attrs.contains(VariableAttributes::NON_VOLATILE));
            assert!(attrs.contains(VariableAttributes::BOOTSERVICE_ACCESS));
            assert!(attrs.contains(VariableAttributes::RUNTIME_ACCESS));
        }

        #[test]
        fn test_attributes_debug() {
            let attrs = VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS;
            let s = format!("{:?}", attrs);
            assert!(s.contains("NON_VOLATILE"));
            assert!(s.contains("RUNTIME_ACCESS"));
        }

        #[test]
        fn test_requires_authentication() {
            let plain = VariableAttributes::DEFAULT_NV_BS_RT;
            assert!(!plain.requires_authentication());

            let auth = VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
            assert!(auth.requires_authentication());
        }
    }

    mod reset_type_tests {
        use super::*;

        #[test]
        fn test_reset_type_values() {
            assert_eq!(ResetType::Cold as u32, 0);
            assert_eq!(ResetType::Warm as u32, 1);
            assert_eq!(ResetType::Shutdown as u32, 2);
            assert_eq!(ResetType::PlatformSpecific as u32, 3);
        }

        #[test]
        fn test_reset_type_from_u32() {
            assert_eq!(ResetType::from_u32(0), Some(ResetType::Cold));
            assert_eq!(ResetType::from_u32(1), Some(ResetType::Warm));
            assert_eq!(ResetType::from_u32(2), Some(ResetType::Shutdown));
            assert_eq!(ResetType::from_u32(3), Some(ResetType::PlatformSpecific));
            assert_eq!(ResetType::from_u32(4), None);
        }

        #[test]
        fn test_reset_type_name() {
            assert_eq!(ResetType::Cold.name(), "Cold");
            assert_eq!(ResetType::Warm.name(), "Warm");
            assert_eq!(ResetType::Shutdown.name(), "Shutdown");
        }

        #[test]
        fn test_reset_type_display() {
            assert_eq!(format!("{}", ResetType::Cold), "Cold");
            assert_eq!(format!("{}", ResetType::Shutdown), "Shutdown");
        }

        #[test]
        fn test_reset_type_default() {
            assert_eq!(ResetType::default(), ResetType::Cold);
        }
    }
}
