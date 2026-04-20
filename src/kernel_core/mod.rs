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

pub mod boundary;
pub mod init;
pub mod process_spawn;
pub mod service;
pub mod spawn;
#[cfg(test)]
#[cfg(test)]
pub mod tests;

pub use boundary::{KernelComponent, is_kernel_component, KERNEL_MODULES};
pub use init::{microkernel_init, microkernel_main};
pub use process_spawn::{spawn_isolated_service, ServiceProcess, IsolationError};
pub use service::{ServiceDescriptor, ServiceId, ServiceState, SERVICE_REGISTRY};
pub use spawn::{spawn_init, spawn_service, SpawnError};
#[cfg(test)]
pub use tests::{run_isolation_checks, validate_service_liveness};
