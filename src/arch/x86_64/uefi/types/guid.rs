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

use crate::arch::x86_64::uefi::constants::{SHA256_HASH_SIZE, SHA384_HASH_SIZE, SHA512_HASH_SIZE};
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
        Self { data1, data2, data3, data4 }
    }

    #[inline]
    pub const fn null() -> Self {
        Self { data1: 0, data2: 0, data3: 0, data4: [0; 8] }
    }

    #[inline]
    pub const fn is_null(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0
            && self.data4[0] == 0 && self.data4[1] == 0 && self.data4[2] == 0
            && self.data4[3] == 0 && self.data4[4] == 0 && self.data4[5] == 0
            && self.data4[6] == 0 && self.data4[7] == 0
    }

    pub const GLOBAL_VARIABLE: Guid = Guid {
        data1: 0x8be4df61, data2: 0x93ca, data3: 0x11d2,
        data4: [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
    };

    pub const IMAGE_SECURITY_DATABASE: Guid = Guid {
        data1: 0xd719b2cb, data2: 0x3d3a, data3: 0x4596,
        data4: [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
    };

    pub const CERT_SHA256: Guid = Guid {
        data1: 0xc1c41626, data2: 0x504c, data3: 0x4092,
        data4: [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
    };

    pub const CERT_SHA384: Guid = Guid {
        data1: 0xff3e5307, data2: 0x9fd0, data3: 0x48c9,
        data4: [0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01],
    };

    pub const CERT_SHA512: Guid = Guid {
        data1: 0x093e0fae, data2: 0xa6c4, data3: 0x4f50,
        data4: [0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a],
    };

    pub const CERT_X509: Guid = Guid {
        data1: 0xa5c059a1, data2: 0x94e4, data3: 0x4aa7,
        data4: [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
    };

    pub const CERT_X509_SHA256: Guid = Guid {
        data1: 0x3bd2a492, data2: 0x96c0, data3: 0x4079,
        data4: [0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed],
    };

    pub const CERT_X509_SHA384: Guid = Guid {
        data1: 0x7076876e, data2: 0x80c2, data3: 0x4ee6,
        data4: [0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b],
    };

    pub const CERT_X509_SHA512: Guid = Guid {
        data1: 0x446dbf63, data2: 0x2502, data3: 0x4cda,
        data4: [0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d],
    };

    pub const NONOS_OWNER: Guid = Guid {
        data1: 0x4E4F4E4F, data2: 0x534F, data3: 0x5345,
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
        if bytes.len() < 16 { return None; }
        Some(Self {
            data1: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            data2: u16::from_le_bytes([bytes[4], bytes[5]]),
            data3: u16::from_le_bytes([bytes[6], bytes[7]]),
            data4: [bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]],
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
        write!(f, "Guid({:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X})",
            self.data1, self.data2, self.data3,
            self.data4[0], self.data4[1], self.data4[2], self.data4[3],
            self.data4[4], self.data4[5], self.data4[6], self.data4[7])
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3,
            self.data4[0], self.data4[1], self.data4[2], self.data4[3],
            self.data4[4], self.data4[5], self.data4[6], self.data4[7])
    }
}

impl Default for Guid {
    fn default() -> Self { Self::null() }
}
