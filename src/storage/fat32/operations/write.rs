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

use crate::storage::block::BlockResult;
use super::super::types::*;
use super::super::SECTOR_BUFFER;

pub fn write_cluster(
    fs: &Fat32,
    cluster: u32,
    data: &[u8],
    write_fn: fn(u8, u64, &[u8]) -> BlockResult<()>,
) -> BlockResult<()> {
    let start_sector = fs.cluster_to_sector(cluster);
    let sector_size = fs.bytes_per_sector as usize;

    let mut offset = 0;
    for s in 0..fs.sectors_per_cluster {
        let sector = start_sector + s as u32;
        // SAFETY: SECTOR_BUFFER is a kernel-internal buffer for FAT32 I/O.
        let sector_buf = unsafe { &mut SECTOR_BUFFER[..sector_size] };

        let copy_len = (data.len() - offset).min(sector_size);
        if copy_len > 0 {
            sector_buf[..copy_len].copy_from_slice(&data[offset..offset + copy_len]);
        }
        for i in copy_len..sector_size {
            sector_buf[i] = 0;
        }

        write_fn(fs.device_id, sector as u64, sector_buf)?;
        offset += sector_size;

        if offset >= data.len() {
            break;
        }
    }

    Ok(())
}
