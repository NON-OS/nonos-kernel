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

use super::core::{MemoryHardening, HARDENING_STATS};
use x86_64::VirtAddr;

impl MemoryHardening {
    pub(super) fn validate_wx_permissions(
        &self,
        _addr: VirtAddr,
        writable: bool,
        executable: bool,
    ) -> Result<(), &'static str> {
        if writable && executable {
            HARDENING_STATS.increment_wx_violations();
            return Err("W^X violation: memory cannot be both writable and executable");
        }
        Ok(())
    }

    pub(super) fn check_guard_page_violation(&self, addr: VirtAddr) -> bool {
        self.guard_pages.read().contains_key(&addr.as_u64())
    }
}
