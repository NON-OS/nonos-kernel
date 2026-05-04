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

pub mod audit;
pub mod crypto;
pub mod file_io;
pub mod process;
pub mod router;
pub mod util;

mod helpers;

// Network and hardware/admin (raw I/O port + MMIO) family routers are
// not on the microkernel trusted path. The router falls through to
// ENOSYS for the corresponding `SyscallNumber` arms when this is off.
// Capsule libc has no use for raw socket/MMIO syscalls; the trusted
// path uses `MkIpc*` and `MkSpawn`/`MkCap*` from `microkernel`.
#[cfg(feature = "nonos-legacy-tree")]
pub mod hardware;
#[cfg(feature = "nonos-legacy-tree")]
pub mod network;

pub use audit::*;
pub use crypto::*;
pub use file_io::*;
pub use process::*;
pub use router::*;
pub use util::*;

#[cfg(feature = "nonos-legacy-tree")]
pub use hardware::*;
#[cfg(feature = "nonos-legacy-tree")]
pub use network::*;
