// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub mod constants;
pub mod controller;
pub mod dma;
mod driver;
pub mod error;
pub mod namespace;
pub mod queue;
pub mod security;
pub mod stats;
pub mod types;
#[cfg(test)]
mod tests;
pub use controller::NvmeController;
pub use controller::SmartLog;
pub use driver::{get_controller, init_nvme, is_initialized, NamespaceInfo, NvmeDriver, NvmeSecurityStats};
pub use error::{NvmeError, NvmeStatusCode};
pub use namespace::Namespace;
pub use stats::{NvmeStats, NvmeStatsSnapshot, SecurityStatsSnapshot};
pub use types::{
    CompletionEntry, CompletionEntry as NvmeCompletion, ControllerCapabilities, ControllerIdentity,
    ControllerVersion, DsmRange, LbaFormat, SubmissionEntry,
};
