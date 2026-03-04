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

pub mod constants;
pub mod types;
pub mod state;
pub mod block_io;
pub mod path;
pub mod listing;
pub mod operations;
pub mod clipboard;
pub mod render;
pub mod input;

pub use types::FmResult;
pub use state::{FM_SELECTED_ITEM, FM_CURRENT_DIR};
pub use path::open_selected;
pub use operations::{create_folder, delete_selected};
pub use clipboard::{copy_selected, cut_selected, paste};
pub use render::draw_file_manager;
pub use input::handle_file_manager_click;
