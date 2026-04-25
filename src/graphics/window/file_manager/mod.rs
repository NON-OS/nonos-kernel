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

pub mod block_io;
pub mod clipboard;
pub mod constants;
pub mod input;
pub mod listing;
pub mod operations;
pub mod path;
pub mod render;
pub mod state;
pub mod types;

pub use clipboard::{copy_selected, cut_selected, paste};
pub use input::{
    cancel_input, handle_file_manager_click, handle_file_manager_key,
    handle_file_manager_special_key,
};
pub use operations::{create_file, create_folder, delete_selected, rename_selected};
pub use path::open_selected;
pub use render::draw_file_manager;
pub use state::{FM_CURRENT_DIR, FM_SELECTED_ITEM};
pub use types::FmResult;

/// Navigate file manager to a specific path
pub fn navigate_to(path: &str) {
    state::set_path(path);
    listing::refresh_listing();
}
