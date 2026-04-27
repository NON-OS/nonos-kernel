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

use super::save::{DATABASE, DB_INITIALIZED, DB_PATH, DB_VERSION};
use super::serialize::deserialize_package;
use super::types::PackageDatabase;
use crate::npkg::error::{NpkgError, NpkgResult};
use core::sync::atomic::Ordering;

pub fn init_database() -> NpkgResult<()> {
    if DB_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let _ = crate::fs::mkdir("/var", 0o755);
    let _ = crate::fs::mkdir("/var/lib", 0o755);
    let _ = crate::fs::mkdir("/var/lib/npkg", 0o755);
    let mut db = PackageDatabase::new();
    if let Ok(data) = crate::fs::read_file_bytes(DB_PATH) {
        load_database(&mut db, &data)?;
    }
    let mut guard = DATABASE.write();
    *guard = Some(db);
    Ok(())
}

fn load_database(db: &mut PackageDatabase, data: &[u8]) -> NpkgResult<()> {
    if data.len() < 8 {
        return Err(NpkgError::DatabaseCorrupt);
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != 0x4E504B47 {
        return Err(NpkgError::DatabaseCorrupt);
    }
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != DB_VERSION {
        return Err(NpkgError::DatabaseCorrupt);
    }
    let mut offset = 8;
    while offset + 4 <= data.len() {
        let entry_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        if offset + entry_len > data.len() {
            break;
        }
        if let Ok(pkg) = deserialize_package(&data[offset..offset + entry_len]) {
            for file in &pkg.files {
                db.file_owners.insert(file.clone(), pkg.meta.name.clone());
            }
            db.packages.insert(pkg.meta.name.clone(), pkg);
        }
        offset += entry_len;
    }
    db.recalculate_stats();
    Ok(())
}
