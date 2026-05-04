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

// `bridge` reaches `lifecycle::manager` and `runner` reaches `download`;
// both are gated capsule modules. `context` is a registry/sandbox query
// helper that the trusted path can keep linked.
#[cfg(feature = "nonos-legacy-tree")]
pub mod bridge;
pub mod context;
#[cfg(feature = "nonos-legacy-tree")]
pub mod runner;

#[cfg(feature = "nonos-legacy-tree")]
pub use bridge::*;
pub use context::*;
#[cfg(feature = "nonos-legacy-tree")]
pub use runner::*;
