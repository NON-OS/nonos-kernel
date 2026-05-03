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

use crate::capabilities::Capability;
use crate::memory::frame_alloc::deallocate_frame;
use crate::syscall::dispatch::util::{errno, require_capability};
use crate::syscall::types::errnos::EINVAL;
use crate::syscall::SyscallResult;

use super::registry::{remove, SurfaceId};

pub fn sys_surface_destroy(id: SurfaceId) -> SyscallResult {
    if let Err(e) = require_capability(Capability::GraphicsSurfaceCreate) {
        return e;
    }
    let Some(proc) = crate::process::current_process() else {
        return errno(EINVAL);
    };
    let Some(surface) = remove(id, proc.pid()) else {
        return errno(EINVAL);
    };
    for frame in surface.frames {
        let _ = deallocate_frame(frame);
    }
    SyscallResult { value: 0, capability_consumed: false, audit_required: true }
}
