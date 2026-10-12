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

//! The settings page: the browser's appearance, the network requests leave
//! through and the manual SOCKS5 proxy, the search template, clearing what
//! the session kept, the reader's defaults and the browser's version. Its
//! geometry is `ui::settings_geom`; its painter `paint::settings`.

mod act;
mod click;
mod keys;
mod net_act;
mod network_line;
mod open;
mod privacy;
mod search_act;

pub use click::click;
pub use keys::key;
pub use network_line::{network_line, NETWORKS};
pub use open::open;
