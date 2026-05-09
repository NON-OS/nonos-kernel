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

//! Reusable index fixtures for host-side wire-layout tests. The
//! signing key is fixed so a regression in the encoder shows up as
//! a stable byte-level diff. None of these fixtures should ever
//! reach a real OS image.

extern crate alloc;

mod key;
mod preview;
mod simple;

pub use key::signing_key;
pub use preview::preview_entry_index;
pub use simple::empty_index;
