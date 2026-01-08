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

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    DeviceNotFound,
    InitializationFailed,
    InvalidBar,
    UnsupportedMode,
    InvalidResolution,
    InvalidColorDepth,
    FramebufferAllocationFailed,
    ModeSetFailed,
    VsyncTimeout,
    InvalidCoordinates,
    OutOfBounds,
    BufferTooSmall,
    InvalidPixelFormat,
    BlitFailed,
    CursorError,
}

impl GpuError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceNotFound => "GPU device not found",
            Self::InitializationFailed => "GPU initialization failed",
            Self::InvalidBar => "Invalid BAR configuration",
            Self::UnsupportedMode => "Unsupported display mode",
            Self::InvalidResolution => "Invalid resolution",
            Self::InvalidColorDepth => "Invalid color depth",
            Self::FramebufferAllocationFailed => "Framebuffer allocation failed",
            Self::ModeSetFailed => "Mode set failed",
            Self::VsyncTimeout => "VSync timeout",
            Self::InvalidCoordinates => "Invalid coordinates",
            Self::OutOfBounds => "Drawing out of bounds",
            Self::BufferTooSmall => "Buffer too small",
            Self::InvalidPixelFormat => "Invalid pixel format",
            Self::BlitFailed => "Blit operation failed",
            Self::CursorError => "Hardware cursor error",
        }
    }

    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::VsyncTimeout | Self::OutOfBounds | Self::InvalidCoordinates
        )
    }
}

impl fmt::Display for GpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type Result<T> = core::result::Result<T, GpuError>;
