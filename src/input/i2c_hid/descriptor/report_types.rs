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

use super::layout_types::{ReportInfo, TouchpadLayout};
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct ReportDescriptor {
    pub data: Vec<u8>,
    pub input_reports: Vec<ReportInfo>,
    pub output_reports: Vec<ReportInfo>,
    pub feature_reports: Vec<ReportInfo>,
    pub has_touchpad: bool,
    pub has_mouse: bool,
    pub has_keyboard: bool,
    pub max_contact_count: u8,
    pub has_x: bool,
    pub has_y: bool,
    pub has_tip: bool,
    pub has_contact_id: bool,
    pub logical_min_x: i32,
    pub logical_min_y: i32,
    pub logical_max_x: i32,
    pub logical_max_y: i32,
    pub physical_max_x: i32,
    pub physical_max_y: i32,
    pub touchpad_layout: TouchpadLayout,
}

impl ReportDescriptor {
    pub fn is_touchpad(&self) -> bool {
        self.has_touchpad && self.has_x && self.has_y
    }
    pub fn is_mouse(&self) -> bool {
        self.has_mouse && self.has_x && self.has_y
    }
}

impl Default for ReportDescriptor {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            input_reports: Vec::new(),
            output_reports: Vec::new(),
            feature_reports: Vec::new(),
            has_touchpad: false,
            has_mouse: false,
            has_keyboard: false,
            max_contact_count: 5,
            has_x: false,
            has_y: false,
            has_tip: false,
            has_contact_id: false,
            logical_min_x: 0,
            logical_min_y: 0,
            logical_max_x: 4096,
            logical_max_y: 4096,
            physical_max_x: 100,
            physical_max_y: 100,
            touchpad_layout: TouchpadLayout::default(),
        }
    }
}
