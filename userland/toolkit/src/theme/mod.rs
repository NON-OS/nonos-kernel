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

pub mod apply;
pub mod chrome;
mod colour;
pub mod contrast;
pub mod derive;
pub mod legible;
mod legible_walk;
mod lift;
pub mod linear;
pub mod palette;
mod roles;
pub mod schemes;
pub mod select;
pub mod store;
mod wash_walk;

pub use apply::apply;
pub use colour::{Opaque, Translucent};
pub use roles::{from_theme, roles, Roles};
pub use schemes::{scheme, Scheme, SCHEMES};
pub use select::theme_of;
pub use store::{snapshot, Theme};
