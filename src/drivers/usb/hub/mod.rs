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

mod constants;
mod types;
mod control;
mod driver;

pub use constants::*;
pub use types::{HubDescriptor, PortStatus, PortState, HubState};
pub use control::{get_hub_descriptor, get_port_status, set_port_feature, clear_port_feature};
pub use control::{power_on_port, reset_port, enable_port, disable_port, clear_connection_change};
pub use driver::{register_hub, init_hub_ports, poll_hub, enumerate_port, hub_count, get_hub};
