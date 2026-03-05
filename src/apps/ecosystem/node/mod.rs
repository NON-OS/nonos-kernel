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

//! NONOS Ecosystem Embedded Node Module.

extern crate alloc;

pub mod config;
pub mod peers;
pub mod state;
pub mod sync;

pub use config::{get_config, set_config, NodeConfig};
pub use peers::{add_peer, get_peers, remove_peer, PeerInfo};
pub use state::{get_state, init, start, stop, NodeState, NodeStatus};
pub use sync::{get_sync_status, SyncStatus};
