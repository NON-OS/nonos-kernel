// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use x86_64::PhysAddr;

#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub framebuffer_type: FramebufferType,
    pub color_info: Option<ColorInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramebufferType {
    Indexed,
    DirectRgb,
    EgaText,
    Unknown(u8),
}

impl From<u8> for FramebufferType {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Indexed,
            1 => Self::DirectRgb,
            2 => Self::EgaText,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ColorInfo {
    pub red_position: u8,
    pub red_mask_size: u8,
    pub green_position: u8,
    pub green_mask_size: u8,
    pub blue_position: u8,
    pub blue_mask_size: u8,
}
