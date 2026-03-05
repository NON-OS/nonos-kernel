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
pub mod state;
pub mod helpers;
pub mod auth;
pub mod session;
pub mod admin;
#[macro_use]
pub mod macros;

pub use types::{ZkId, Capability, AuthChallenge, AuthResponse, AuthSession, ZkidsManager, ZkidsConfig, ZkidsStats};
pub use auth::{init_zkids, register_zkid, create_auth_challenge, authenticate_with_zkproof};
pub use session::{validate_session, has_capability, cleanup_expired, get_zkids_stats};
pub use admin::{export_zkid, import_zkid};
