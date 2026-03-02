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

extern crate alloc;

pub mod buffer;
pub mod command;
pub mod input;
pub mod mode;
pub mod motion;
pub mod render;
pub mod state;

pub use buffer::{Buffer, Line};
pub use command::{execute_command, Command};
pub use input::{handle_input, InputResult, Key};
pub use mode::Mode;
pub use motion::{Motion, MotionResult};
pub use render::{render, RenderConfig};
pub use state::{Editor, EditorConfig};
