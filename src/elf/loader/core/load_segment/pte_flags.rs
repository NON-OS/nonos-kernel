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

use crate::elf::types::ProgramHeader;
use crate::memory::paging::types::PagePermissions;

pub(super) fn pte_perms_from_phdr(ph: &ProgramHeader) -> PagePermissions {
    let mut perms = PagePermissions::READ | PagePermissions::USER;
    if ph.is_writable() {
        perms = perms | PagePermissions::WRITE;
    }
    if ph.is_executable() {
        perms = perms | PagePermissions::EXECUTE;
    }
    perms
}
