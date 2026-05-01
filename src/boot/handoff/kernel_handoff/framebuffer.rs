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

// Cross-architecture framebuffer descriptor. Optional on every arch:
// headless boots have no framebuffer. Each arch's per-arch handoff
// type carries pixel-format details; the kernel core only needs the
// physical layout, the framebuffer's location, and the bootloader's
// final cursor row so the early boot log can continue at the right
// vertical position.

#[derive(Debug, Clone, Copy)]
pub struct Framebuffer {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub cursor_y: u32,
}
