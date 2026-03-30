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

use super::{state, HidDeviceType};

#[derive(Debug, Clone)]
pub struct TouchpadDebugInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub using_layout: bool,
    pub logical_max_x: i32,
    pub logical_max_y: i32,
    pub has_tip: bool,
    pub has_contact_id: bool,
    pub max_contacts: u8,
    pub update_count: u32,
}

pub fn get_touchpad_debug_info() -> Option<TouchpadDebugInfo> {
    let devices = state::DEVICES.lock();
    for dev in devices.iter() {
        if matches!(dev.device_type(), HidDeviceType::Touchpad | HidDeviceType::Mouse) {
            let hid_desc = dev.hid_descriptor();
            let report_desc = dev.report_descriptor();
            let (max_x, max_y) = dev.touchpad_logical_max();
            return Some(TouchpadDebugInfo {
                vendor_id: hid_desc.vendor_id,
                product_id: hid_desc.product_id,
                using_layout: dev.is_using_layout(),
                logical_max_x: max_x,
                logical_max_y: max_y,
                has_tip: report_desc.has_tip,
                has_contact_id: report_desc.has_contact_id,
                max_contacts: report_desc.max_contact_count,
                update_count: state::get_update_count(),
            });
        }
    }
    None
}
