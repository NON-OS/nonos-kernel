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

pub mod types;
mod checks;
mod presets;

#[cfg(test)]
mod tests;

pub use types::{Capability, CapabilitySet};

pub use presets::{
    standard_user_capabilities,
    privileged_capabilities,
    system_capabilities,
    full_capabilities,
    sandboxed_capabilities,
    network_service_capabilities,
};
