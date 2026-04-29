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

mod close;
mod minimize;
mod open;
mod query;
mod resize;
mod state;
mod transform;

pub use close::start_close;
pub use minimize::{start_minimize, start_restore};
pub use open::start_open;
pub use query::{get_animation, has_animation, is_animating, remove_animation, tick_animations};
pub use resize::start_resize;
pub use state::{AnimationType, WindowAnimation};
pub use transform::{apply_transform, WindowTransform};
