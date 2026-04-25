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

use super::loader_parse::{bytes_to_manifest, manifest_to_bytes};
use super::manifest::AppManifest;
use alloc::vec::Vec;

pub struct AppPackage {
    pub manifest: AppManifest,
    pub binary: Vec<u8>,
    pub icon: Vec<u8>,
}

pub fn pack_app(manifest: &AppManifest, binary: &[u8], icon: &[u8]) -> Vec<u8> {
    let mut pkg = Vec::new();
    pkg.extend_from_slice(b"NOXPKG\x01\x00");
    let m_bytes = manifest_to_bytes(manifest);
    pkg.extend_from_slice(&(m_bytes.len() as u32).to_le_bytes());
    pkg.extend_from_slice(&m_bytes);
    pkg.extend_from_slice(&(binary.len() as u32).to_le_bytes());
    pkg.extend_from_slice(binary);
    pkg.extend_from_slice(&(icon.len() as u32).to_le_bytes());
    pkg.extend_from_slice(icon);
    pkg
}

pub fn unpack_app(data: &[u8]) -> Option<AppPackage> {
    if data.len() < 16 || &data[..6] != b"NOXPKG" {
        return None;
    }
    let mut pos = 8;
    let m_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + m_len > data.len() {
        return None;
    }
    let manifest = bytes_to_manifest(&data[pos..pos + m_len])?;
    pos += m_len;
    let b_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    if pos + b_len > data.len() {
        return None;
    }
    let binary = data[pos..pos + b_len].to_vec();
    pos += b_len;
    let i_len =
        u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    let icon = if pos + i_len <= data.len() { data[pos..pos + i_len].to_vec() } else { Vec::new() };
    Some(AppPackage { manifest, binary, icon })
}
