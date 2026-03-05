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

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU8, AtomicUsize};

pub const MAX_WINDOWS: usize = 8;
pub(crate) const TITLE_BAR_HEIGHT: u32 = 28;
pub const WINDOW_PADDING: u32 = 2;
pub(crate) const SCROLLBAR_WIDTH: u32 = 12;
pub(crate) const SCROLLBAR_MIN_THUMB: u32 = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WindowType {
    None = 0,
    FileManager = 1,
    Calculator = 2,
    TextEditor = 3,
    Settings = 4,
    About = 5,
    ProcessManager = 6,
    Browser = 7,
    Terminal = 8,
    Wallet = 9,
    Ecosystem = 10,
}

pub(crate) const RESIZE_BORDER: i32 = 6;
pub(crate) const MIN_WINDOW_WIDTH: u32 = 200;
pub(crate) const MIN_WINDOW_HEIGHT: u32 = 150;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum ResizeEdge {
    #[default]
    None = 0,
    Top = 1,
    Bottom = 2,
    Left = 3,
    Right = 4,
    TopLeft = 5,
    TopRight = 6,
    BottomLeft = 7,
    BottomRight = 8,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SnapZone {
    #[default]
    None = 0,
    Left = 1,
    Right = 2,
    Top = 3,
    TopLeft = 4,
    TopRight = 5,
    BottomLeft = 6,
    BottomRight = 7,
}

impl SnapZone {
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Left,
            2 => Self::Right,
            3 => Self::Top,
            4 => Self::TopLeft,
            5 => Self::TopRight,
            6 => Self::BottomLeft,
            7 => Self::BottomRight,
            _ => Self::None,
        }
    }
}

pub(crate) const SNAP_THRESHOLD: i32 = 20;

pub struct Window {
    pub active: AtomicBool,
    pub minimized: AtomicBool,
    pub maximized: AtomicBool,
    pub window_type: AtomicU32,
    pub x: AtomicI32,
    pub y: AtomicI32,
    pub width: AtomicU32,
    pub height: AtomicU32,
    pub dragging: AtomicBool,
    pub drag_offset_x: AtomicI32,
    pub drag_offset_y: AtomicI32,
    pub scroll_x: AtomicI32,
    pub scroll_y: AtomicI32,
    pub content_height: AtomicU32,
    pub content_width: AtomicU32,
    pub scrollbar_dragging: AtomicBool,
    pub scrollbar_drag_offset: AtomicI32,
    pub resizing: AtomicBool,
    pub resize_edge: AtomicU8,
    pub resize_start_x: AtomicI32,
    pub resize_start_y: AtomicI32,
    pub resize_start_w: AtomicU32,
    pub resize_start_h: AtomicU32,
    pub pre_max_x: AtomicI32,
    pub pre_max_y: AtomicI32,
    pub pre_max_w: AtomicU32,
    pub pre_max_h: AtomicU32,
    pub snapped: AtomicBool,
    pub snap_zone: AtomicU8,
    pub pending_snap: AtomicU8,
    pub pre_snap_x: AtomicI32,
    pub pre_snap_y: AtomicI32,
    pub pre_snap_w: AtomicU32,
    pub pre_snap_h: AtomicU32,
}

impl Window {
    pub(crate) const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            minimized: AtomicBool::new(false),
            maximized: AtomicBool::new(false),
            window_type: AtomicU32::new(0),
            x: AtomicI32::new(0),
            y: AtomicI32::new(0),
            width: AtomicU32::new(0),
            height: AtomicU32::new(0),
            dragging: AtomicBool::new(false),
            drag_offset_x: AtomicI32::new(0),
            drag_offset_y: AtomicI32::new(0),
            scroll_x: AtomicI32::new(0),
            scroll_y: AtomicI32::new(0),
            content_height: AtomicU32::new(0),
            content_width: AtomicU32::new(0),
            scrollbar_dragging: AtomicBool::new(false),
            scrollbar_drag_offset: AtomicI32::new(0),
            resizing: AtomicBool::new(false),
            resize_edge: AtomicU8::new(0),
            resize_start_x: AtomicI32::new(0),
            resize_start_y: AtomicI32::new(0),
            resize_start_w: AtomicU32::new(0),
            resize_start_h: AtomicU32::new(0),
            pre_max_x: AtomicI32::new(0),
            pre_max_y: AtomicI32::new(0),
            pre_max_w: AtomicU32::new(0),
            pre_max_h: AtomicU32::new(0),
            snapped: AtomicBool::new(false),
            snap_zone: AtomicU8::new(0),
            pending_snap: AtomicU8::new(0),
            pre_snap_x: AtomicI32::new(0),
            pre_snap_y: AtomicI32::new(0),
            pre_snap_w: AtomicU32::new(0),
            pre_snap_h: AtomicU32::new(0),
        }
    }
}

impl ResizeEdge {
    pub(crate) fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Top,
            2 => Self::Bottom,
            3 => Self::Left,
            4 => Self::Right,
            5 => Self::TopLeft,
            6 => Self::TopRight,
            7 => Self::BottomLeft,
            8 => Self::BottomRight,
            _ => Self::None,
        }
    }
}

pub static WINDOWS: [Window; MAX_WINDOWS] = [
    Window::new(), Window::new(), Window::new(), Window::new(),
    Window::new(), Window::new(), Window::new(), Window::new(),
];

pub static FOCUSED_WINDOW: AtomicUsize = AtomicUsize::new(MAX_WINDOWS);
pub(super) static NEXT_WINDOW_OFFSET: AtomicI32 = AtomicI32::new(0);

pub fn window_type_from_u32(val: u32) -> WindowType {
    match val {
        1 => WindowType::FileManager,
        2 => WindowType::Calculator,
        3 => WindowType::TextEditor,
        4 => WindowType::Settings,
        5 => WindowType::About,
        6 => WindowType::ProcessManager,
        7 => WindowType::Browser,
        8 => WindowType::Terminal,
        9 => WindowType::Wallet,
        10 => WindowType::Ecosystem,
        _ => WindowType::None,
    }
}

pub(crate) fn get_window_title(wtype: WindowType) -> &'static [u8] {
    match wtype {
        WindowType::FileManager => b"Files",
        WindowType::Calculator => b"Calculator",
        WindowType::TextEditor => b"Editor",
        WindowType::Settings => b"Settings",
        WindowType::About => b"About N\xd8NOS",
        WindowType::ProcessManager => b"Processes",
        WindowType::Browser => b"Browser",
        WindowType::Terminal => b"Terminal",
        WindowType::Wallet => b"Wallet",
        WindowType::Ecosystem => b"N\xd8NOS Ecosystem",
        WindowType::None => b"",
    }
}
