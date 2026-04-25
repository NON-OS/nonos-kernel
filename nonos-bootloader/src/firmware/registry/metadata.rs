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

use crate::firmware::detection::version::FirmwareVersion;

#[derive(Debug, Clone)]
pub struct FirmwareMetadata { pub version: FirmwareVersion, pub vendor: [u8; 32], pub description: [u8; 64], pub checksum: [u8; 32], pub size: u32, pub features: u32, pub compatibility_flags: u16 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataField { Version, Vendor, Description, Checksum, Size, Features, Compatibility }

pub fn extract_metadata(firmware_data: &[u8]) -> Option<FirmwareMetadata> {
    if firmware_data.len() < 128 { return None; }
    let mut metadata = FirmwareMetadata::default();
    if let Some(header_offset) = find_metadata_header(firmware_data) {
        parse_metadata_from_offset(firmware_data, header_offset, &mut metadata);
    } else {
        extract_embedded_metadata(firmware_data, &mut metadata);
    }
    Some(metadata)
}

pub fn validate_metadata(metadata: &FirmwareMetadata) -> bool {
    if metadata.size == 0 || metadata.size > 64 * 1024 * 1024 { return false; }
    if metadata.vendor.iter().all(|&b| b == 0) { return false; }
    if metadata.checksum.iter().all(|&b| b == 0) { return false; }
    if metadata.version.major == 0 && metadata.version.minor == 0 { return false; }
    true
}

impl Default for FirmwareMetadata {
    fn default() -> Self {
        Self { version: FirmwareVersion::default(), vendor: [0; 32], description: [0; 64], checksum: [0; 32], size: 0, features: 0, compatibility_flags: 0 }
    }
}

fn find_metadata_header(data: &[u8]) -> Option<usize> {
    const METADATA_MAGIC: &[u8] = b"FWMD";
    data.windows(4).position(|window| window == METADATA_MAGIC)
}

fn parse_metadata_from_offset(data: &[u8], offset: usize, metadata: &mut FirmwareMetadata) {
    if offset + 128 > data.len() { return; }
    let meta_data = &data[offset + 4..offset + 128];
    metadata.version.major = meta_data[0];
    metadata.version.minor = meta_data[1];
    metadata.version.patch = u16::from_le_bytes([meta_data[2], meta_data[3]]);
    metadata.vendor[..32].copy_from_slice(&meta_data[4..36]);
    metadata.checksum[..32].copy_from_slice(&meta_data[36..68]);
    metadata.size = u32::from_le_bytes([meta_data[68], meta_data[69], meta_data[70], meta_data[71]]);
    metadata.features = u32::from_le_bytes([meta_data[72], meta_data[73], meta_data[74], meta_data[75]]);
}

fn extract_embedded_metadata(data: &[u8], metadata: &mut FirmwareMetadata) {
    metadata.size = data.len() as u32;
    metadata.vendor[..4].copy_from_slice(b"UNKN");
    if data.len() >= 8 { metadata.version.major = data[0]; metadata.version.minor = data[1]; }
}