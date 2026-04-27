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

use super::types::*;
use alloc::vec::Vec;

pub fn build_auxv(loaded: &LoadedElf, exec_name_addr: u64, random_addr: u64) -> Vec<(u64, u64)> {
    let mut auxv = Vec::new();
    auxv.push((AT_PHDR, loaded.phdr_addr));
    auxv.push((AT_PHENT, loaded.phentsize as u64));
    auxv.push((AT_PHNUM, loaded.phnum as u64));
    auxv.push((AT_PAGESZ, 4096));
    auxv.push((AT_BASE, loaded.base_addr));
    auxv.push((AT_ENTRY, loaded.entry));
    auxv.push((AT_UID, 0));
    auxv.push((AT_EUID, 0));
    auxv.push((AT_GID, 0));
    auxv.push((AT_EGID, 0));
    auxv.push((AT_SECURE, 0));
    auxv.push((AT_RANDOM, random_addr));
    auxv.push((AT_EXECFN, exec_name_addr));
    auxv.push((AT_NULL, 0));
    auxv
}
