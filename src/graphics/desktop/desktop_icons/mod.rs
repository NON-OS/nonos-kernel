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

mod click;
mod fs_ops;
mod path;
mod render;
mod state;

pub(super) use click::{handle_click, handle_drag, handle_drag_end, is_dragging};
pub(super) use fs_ops::{
    clear_selection, create_file, create_folder, delete_selected, has_selection,
};
pub(super) use path::{navigate_back, navigate_into};
pub(super) use render::draw;
pub(super) use state::{get_current_path, is_in_subfolder, refresh};
