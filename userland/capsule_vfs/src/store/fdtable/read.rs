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

use alloc::vec::Vec;

use super::types::{Store, StoreError};

impl Store {
    pub fn read(&mut self, fd: u32, owner_pid: u32, max: usize) -> Result<Vec<u8>, StoreError> {
        let (file_idx, pos) = {
            let entry = self.entry(fd, owner_pid)?;
            (entry.file_idx, entry.pos)
        };
        let data = &self.files[file_idx].data;
        let avail = data.len().saturating_sub(pos);
        let n = if max < avail { max } else { avail };
        let out = data[pos..pos + n].to_vec();
        if let Some(entry) = self.fds[fd as usize].as_mut() {
            entry.pos = pos + n;
        }
        Ok(out)
    }
}
