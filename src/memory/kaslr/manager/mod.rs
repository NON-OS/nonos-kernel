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

mod derive;
mod entropy;
mod hwrng;
mod init;
mod slide;
mod state;
mod validate;

pub use derive::derive_subkey;
pub use hwrng::has_hardware_rng;
pub use init::{boot_nonce, get_slide, init, is_initialized};
pub use validate::{validate, verify_slide_integrity};
