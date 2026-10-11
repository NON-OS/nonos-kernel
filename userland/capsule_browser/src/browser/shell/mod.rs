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

//! What belongs to the window rather than to the page in it: the sidebar
//! mode, the page the content area shows, the visit log, bookmarks and
//! downloads. Pure but for the file server calls, which the host proofs
//! leave out.

pub mod bookmarks;
pub mod clock;
pub mod dl_line;
pub mod dl_name;
pub mod downloads;
#[cfg(not(feature = "harness"))]
pub mod save_dl;
pub mod site_label;
pub mod store;
pub mod types;
pub mod visits;
pub mod window;
mod window_keep;

pub use types::Page;
pub use window::Shell;
