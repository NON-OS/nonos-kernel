// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pub mod apps;
pub mod backgrounds;
pub mod borders;
pub mod buttons;
pub mod chrome;
pub mod dark;
pub mod glass;
pub mod light;
pub mod semantic;
pub mod text;
pub mod theme;
pub mod utils;

pub use apps::*;
pub use backgrounds::*;
pub use borders::*;
pub use buttons::*;
pub use chrome::*;
pub use glass::*;
pub use semantic::*;
pub use text::*;
pub use theme::{get_theme, is_dark_mode, set_theme, Theme};
pub use utils::*;
