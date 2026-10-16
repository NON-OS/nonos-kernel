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

//! The toolkit's theme modules, included so the proofs run the real source.
//!
//! The shape mirrors `toolkit/src/theme` exactly, because each included file
//! resolves its siblings through `super::`. A shim that renamed or flattened
//! anything here would be proving a different arrangement than the one that ships.

#[path = "../../../toolkit/src/theme/chrome/mod.rs"]
pub mod chrome;
#[path = "../../../toolkit/src/theme/colour.rs"]
pub mod colour;
#[path = "../../../toolkit/src/theme/contrast.rs"]
pub mod contrast;
#[path = "../../../toolkit/src/theme/derive.rs"]
pub mod derive;
#[path = "../../../toolkit/src/theme/legible.rs"]
pub mod legible;
#[path = "../../../toolkit/src/theme/legible_walk.rs"]
pub mod legible_walk;
#[path = "../../../toolkit/src/theme/linear.rs"]
pub mod linear;
#[path = "../../../toolkit/src/theme/palette.rs"]
pub mod palette;
#[path = "../../../toolkit/src/theme/roles/mod.rs"]
pub mod roles;
#[path = "../../../toolkit/src/theme/schemes/mod.rs"]
pub mod schemes;
#[path = "../../../toolkit/src/theme/select.rs"]
pub mod select;
#[path = "../../../toolkit/src/theme/store/mod.rs"]
pub mod store;
