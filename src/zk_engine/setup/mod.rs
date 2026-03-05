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

//! Groth16 trusted setup (CRS generation).

mod powers;
mod params;
mod trusted;
mod verification;

pub use powers::*;
pub use params::*;
pub use trusted::*;
pub use verification::*;

// Re-export from groth16 for backwards compatibility
pub use crate::zk_engine::groth16::{VerifyingKey, ProvingKey};
