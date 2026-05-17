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

pub struct Frame<'a> {
    pub buf: &'a mut [u32],
    pub stride: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Default)]
pub struct InputEvent {
    pub kind: u16,
    pub code: u32,
    pub x: i32,
    pub y: i32,
    pub delta_x: i32,
    pub delta_y: i32,
}

pub const KIND_KEY_DOWN: u16 = 0;
pub const KIND_BUTTON_DOWN: u16 = 5;

pub struct WindowCfg {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub z: u32,
}

pub trait App {
    fn window(&self) -> WindowCfg;
    fn init(&mut self) {}
    fn on_input(&mut self, ev: InputEvent) -> bool {
        let _ = ev;
        false
    }
    fn render(&mut self, f: &mut Frame);
}
