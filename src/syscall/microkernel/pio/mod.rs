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

// `MkPioGrant` / `MkPioRead` / `MkPioWrite` / `MkPioRelease` handlers.
// PIO is an x86-only instruction class; non-x86 builds fail-closed
// with `-ENOSYS` (38) so capsule libc sees a precise unsupported
// instead of a silent zero or a link failure. The kernel is the only
// side that ever executes `in`/`out`; userland walks every access
// through these handlers.

#[cfg(target_arch = "x86_64")]
mod errno;
#[cfg(target_arch = "x86_64")]
mod grant;
#[cfg(target_arch = "x86_64")]
mod read;
#[cfg(target_arch = "x86_64")]
mod release;
#[cfg(target_arch = "x86_64")]
mod width;
#[cfg(target_arch = "x86_64")]
mod write;

#[cfg(target_arch = "x86_64")]
pub use grant::sys_pio_grant;
#[cfg(target_arch = "x86_64")]
pub use read::sys_pio_read;
#[cfg(target_arch = "x86_64")]
pub use release::sys_pio_release;
#[cfg(target_arch = "x86_64")]
pub use write::sys_pio_write;

#[cfg(not(target_arch = "x86_64"))]
mod stub;
#[cfg(not(target_arch = "x86_64"))]
pub use stub::{sys_pio_grant, sys_pio_read, sys_pio_release, sys_pio_write};
