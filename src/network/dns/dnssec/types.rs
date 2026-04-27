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

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

pub const DNSKEY_TYPE: u16 = 48;
pub const RRSIG_TYPE: u16 = 46;
pub const DS_TYPE: u16 = 43;
pub const NSEC_TYPE: u16 = 47;
pub const NSEC3_TYPE: u16 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnssecAlgorithm {
    RsaSha1 = 5,
    RsaSha256 = 8,
    RsaSha512 = 10,
    EcdsaP256Sha256 = 13,
    EcdsaP384Sha384 = 14,
    Ed25519 = 15,
    Ed448 = 16,
}

impl DnssecAlgorithm {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            5 => Some(Self::RsaSha1),
            8 => Some(Self::RsaSha256),
            10 => Some(Self::RsaSha512),
            13 => Some(Self::EcdsaP256Sha256),
            14 => Some(Self::EcdsaP384Sha384),
            15 => Some(Self::Ed25519),
            16 => Some(Self::Ed448),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: DnssecAlgorithm,
    pub public_key: Vec<u8>,
    pub key_tag: u16,
}

#[derive(Debug, Clone)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: DnssecAlgorithm,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RrsigRecord {
    pub type_covered: u16,
    pub algorithm: DnssecAlgorithm,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NsecRecord {
    pub next_domain: String,
    pub types_bitmap: Vec<u8>,
}
