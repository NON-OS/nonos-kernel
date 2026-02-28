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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    Side1 = 3,
    Side2 = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseMoveEvent {
    pub dx: i16,
    pub dy: i16,
    pub abs_x: Option<u16>,
    pub abs_y: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseButtonEvent {
    pub button: MouseButton,
    pub pressed: bool,
    pub click_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseScrollEvent {
    pub delta_y: i8,
    pub delta_x: i8,
}
