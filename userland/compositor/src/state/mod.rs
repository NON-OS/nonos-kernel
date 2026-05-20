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

pub mod attach;
pub mod context;
pub mod cursor;
pub mod damage;
pub mod focus;
pub mod scene;
pub mod scene_remove;

pub use attach::AttachCache;
pub use context::{Context, PresentMode};
pub use cursor::CursorTracker;
pub use damage::DamageAccumulator;
pub use focus::FocusTable;
pub use scene::{Layer, SceneTable};
