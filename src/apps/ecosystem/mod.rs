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

//! NONOS Ecosystem Application.

extern crate alloc;

pub mod browser;
pub mod lp;
pub mod node;
pub mod privacy;
pub mod staking;
pub mod wallet;

mod app;
mod tabs;

pub use app::{init, is_running, start, stop, is_initialized, EcosystemApp, APP_INFO};
pub use tabs::{current_tab, set_tab, next_tab, prev_tab, Tab};
