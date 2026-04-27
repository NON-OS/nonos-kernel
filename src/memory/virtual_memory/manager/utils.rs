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

use super::super::types::VmProtection;
use crate::memory::paging;

pub(super) fn protection_to_page_permissions(protection: VmProtection) -> paging::PagePermissions {
    match protection {
        VmProtection::None => paging::PagePermissions::READ.remove(paging::PagePermissions::READ),
        VmProtection::Read => paging::PagePermissions::READ,
        VmProtection::ReadWrite => paging::PagePermissions::READ | paging::PagePermissions::WRITE,
        VmProtection::ReadExecute => {
            paging::PagePermissions::READ | paging::PagePermissions::EXECUTE
        }
        VmProtection::ReadWriteExecute => {
            paging::PagePermissions::READ
                | paging::PagePermissions::WRITE
                | paging::PagePermissions::EXECUTE
        }
    }
}

pub(super) fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}
