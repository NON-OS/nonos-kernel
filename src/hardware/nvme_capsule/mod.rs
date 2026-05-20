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

//! Kernel-side glue for the NVMe userland driver capsule.
//! The kernel embeds and spawns the signed capsule, then speaks the
//! admin/status IPC contract. PCIe claim, BAR0 mapping, MSI-X, admin
//! queue DMA, Identify, and SMART log reads stay inside `driver.nvme0`.

mod capability;
pub mod client;
pub(crate) mod embed;
mod error;
mod protocol;
mod spawn;
mod state;

pub use client::{
    controller_info, healthcheck, identify_controller, identify_namespace, smart_health,
    NvmeControllerIdentity, NvmeControllerInfo, NvmeNamespaceIdentity, NvmeSmartHealth,
};
pub use error::DriverNvmeError;
pub use spawn::{spawn_driver_nvme_capsule, SpawnError};
pub use state::shared_state;
