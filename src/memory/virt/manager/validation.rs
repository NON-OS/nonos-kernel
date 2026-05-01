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

use super::super::error::{VmError, VmResult};
use super::super::stats::VM_STATS;
use super::super::types::{PageSize, VmFlags};
use super::core::VirtualMemoryManager;
use crate::memory::addr::{PhysAddr, VirtAddr};

impl VirtualMemoryManager {
    pub(super) fn validate_wx_permissions(&self, flags: VmFlags) -> VmResult<()> {
        let writable = flags.contains(VmFlags::Write);
        let executable = !flags.contains(VmFlags::NoExecute);
        if writable && executable {
            VM_STATS.record_wx_violation();
            return Err(VmError::WXViolation);
        }
        Ok(())
    }

    pub(super) fn validate_alignment(
        &self,
        va: VirtAddr,
        pa: PhysAddr,
        page_size: PageSize,
    ) -> VmResult<()> {
        if !page_size.is_aligned(va.as_u64()) || !page_size.is_aligned(pa.as_u64()) {
            return Err(VmError::InvalidAlignment);
        }
        Ok(())
    }
}
