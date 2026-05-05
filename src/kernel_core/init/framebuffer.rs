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

use crate::boot::handoff::BootHandoffV1;

// The microkernel does not own a graphics surface. Trusted-path log
// goes to serial via `sys::boot_log`. This stays as a typed no-op so
// the arch-specific init match still has a hook to call without each
// caller branching on the absence of a framebuffer subsystem.
pub fn init_framebuffer(_handoff: &BootHandoffV1) {}
