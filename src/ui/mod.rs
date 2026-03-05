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

#[cfg(feature = "ui")]
pub mod browser;
#[cfg(feature = "ui")]
pub mod cli;
#[cfg(feature = "ui")]
pub mod clipboard;
#[cfg(feature = "ui")]
pub mod desktop;
#[cfg(feature = "ui")]
pub mod event;
#[cfg(feature = "ui")]
pub mod gui;
#[cfg(feature = "ui")]
mod init;
#[cfg(feature = "ui")]
pub mod keyboard;
#[cfg(feature = "ui")]
pub mod tui;

#[cfg(feature = "ui")]
pub use browser::*;
#[cfg(feature = "ui")]
pub use cli::*;
#[cfg(feature = "ui")]
pub use clipboard::*;
#[cfg(feature = "ui")]
pub use desktop::*;
#[cfg(feature = "ui")]
pub use event::*;
#[cfg(feature = "ui")]
pub use init::{create_window, init_ui_subsystems};
