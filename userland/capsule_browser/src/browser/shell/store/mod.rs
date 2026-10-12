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

//! The window's state kept across runs in `/home/.browser/state.bin`. The
//! record, its merge and its paths are pure, so the host proofs compile
//! them; the file server calls are left out of the proofs.

pub mod codec;
mod cursor;
pub mod decode;
#[cfg(not(feature = "harness"))]
pub mod gate;
#[cfg(not(feature = "harness"))]
mod load;
pub mod merge;
pub mod paths;
mod put;
pub mod record;
#[cfg(not(feature = "harness"))]
mod save;
#[cfg(not(feature = "harness"))]
mod sync;

pub use codec::Persisted;
#[cfg(not(feature = "harness"))]
pub use load::load;
#[cfg(not(feature = "harness"))]
pub use sync::sync;
