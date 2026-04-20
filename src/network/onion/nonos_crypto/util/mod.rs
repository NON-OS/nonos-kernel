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

mod mem;
mod rng;
#[cfg(test)]
#[cfg(test)]
mod tests;
mod wrappers;

pub use mem::{constant_time_eq, secure_memzero, conditional_select};
pub use rng::{VaultRng, generate_seed};
#[cfg(test)]
pub use tests::run_comprehensive_tests;
pub use wrappers::{rand32, sha256};
