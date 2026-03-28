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

mod state;
mod path;
mod render;
mod click;
mod fs_ops;

pub(super) use state::{refresh, get_current_path, is_in_subfolder};
pub(super) use path::{navigate_into, navigate_back};
pub(super) use render::draw;
pub(super) use click::{handle_click, handle_drag, handle_drag_end, is_dragging};
pub(super) use fs_ops::{create_folder, create_file, delete_selected, has_selection, clear_selection};
