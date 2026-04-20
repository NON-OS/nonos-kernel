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

pub mod caps;
pub mod protocol;
pub mod registry;
pub mod client;
pub mod server;

pub use caps::{ServiceCap, check_service_cap, verify_caller_cap, has_capability, CapError};
pub use caps::{
    CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO, CAP_INPUT,
    CAP_AUDIO, CAP_ZK, CAP_GPU, CAP_APPS, CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
};
pub use protocol::{ServiceRequest, ServiceResponse, ServiceMessage};
pub use registry::{lookup_service, register_endpoint, ServiceEndpoint};
pub use client::ServiceClient;
pub use server::ServiceServer;

#[cfg(test)]
#[cfg(test)]
pub mod tests;
