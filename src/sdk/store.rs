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

use super::manifest::AppManifest;
use super::registry::register_app_with_stats;

const STORE_PATH: &str = "/ram/apps/store.idx";

pub(super) fn load_store_index() {
    if let Ok(data) = crate::fs::ramfs::read_file(STORE_PATH) {
        parse_store_index(&data);
    }
}

pub fn publish_app(manifest: &AppManifest) -> bool {
    register_app_with_stats(manifest.clone(), 0).is_some()
}

fn parse_store_index(data: &[u8]) {
    for chunk in data.chunks(512) {
        if chunk.len() < 128 {
            continue;
        }
        let mut m = AppManifest::empty();
        m.name[..64.min(chunk.len())].copy_from_slice(&chunk[..64.min(chunk.len())]);
        if chunk.len() >= 80 {
            m.version[..16].copy_from_slice(&chunk[64..80]);
        }
        if chunk.len() >= 144 {
            m.author[..64].copy_from_slice(&chunk[80..144]);
        }
        if chunk.len() >= 145 {
            m.category = chunk[144];
        }
        if chunk.len() >= 149 {
            m.price_nox = u32::from_le_bytes([chunk[145], chunk[146], chunk[147], chunk[148]]);
        }
        let installs = if chunk.len() >= 153 {
            u32::from_le_bytes([chunk[149], chunk[150], chunk[151], chunk[152]])
        } else {
            0
        };
        register_app_with_stats(m, installs);
    }
}

pub fn fetch_remote_index() -> Result<(), &'static str> {
    Err("Network store not available")
}
