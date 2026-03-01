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

mod chain;
mod constants;
mod error;
mod verify;

pub use chain::CapabilityChain;
pub use constants::{max_chain_depth, MAX_CHAIN_DEPTH};
pub use error::ChainError;
pub use verify::{
    effective_capabilities, first_invalid_index, is_chain_valid, verify_all_capabilities,
    verify_chain, verify_chain_capability,
};
