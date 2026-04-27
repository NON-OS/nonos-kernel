// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::core::LibraryManager;
use crate::elf::errors::ElfResult;
use alloc::vec::Vec;

impl LibraryManager {
    pub fn initialize_all(&mut self) -> ElfResult<usize> {
        let ids: Vec<usize> = self.load_order.clone();
        let mut count = 0;
        for id in ids {
            self.initialize(id)?;
            count += 1;
        }
        Ok(count)
    }

    pub fn finalize_all(&mut self) -> ElfResult<usize> {
        let ids: Vec<usize> = self.load_order.iter().rev().copied().collect();
        let mut count = 0;
        for id in ids {
            self.finalize(id)?;
            count += 1;
        }
        Ok(count)
    }
}
