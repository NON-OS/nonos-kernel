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

use super::constants::MAX_CONTACTS;
use super::types::{TouchPoint, TouchpadState};

pub(crate) fn try_parse_hp_precision_touchpad(
    data: &[u8],
    state: &mut TouchpadState,
    max_contacts: u8,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    // HP Precision Touchpad format (with scan time):
    // Byte 0-1: Scan time (16-bit)
    // Byte 2: Contact count (lower 5 bits)
    // For each contact (5 bytes each):
    //   Byte 0: Flags (bit 0 = tip, bit 1 = confidence, bits 2-7 = contact ID)
    //   Byte 1-2: X position (16-bit LE)
    //   Byte 3-4: Y position (16-bit LE)
    // After contacts: Button byte

    if data.len() < 3 {
        return false;
    }

    // Try offset 2 first (after 2-byte scan time) - common HP format
    if let Some(result) = try_parse_at_offset(data, 2, max_contacts, logical_max_x, logical_max_y) {
        *state = result;
        return true;
    }

    // Try offset 0 (no scan time) - some touchpads
    if let Some(result) = try_parse_at_offset(data, 0, max_contacts, logical_max_x, logical_max_y) {
        *state = result;
        return true;
    }

    // Try offset 3 (3-byte header) - less common
    if let Some(result) = try_parse_at_offset(data, 3, max_contacts, logical_max_x, logical_max_y) {
        *state = result;
        return true;
    }

    false
}

fn try_parse_at_offset(
    data: &[u8],
    header_offset: usize,
    max_contacts: u8,
    logical_max_x: i32,
    logical_max_y: i32,
) -> Option<TouchpadState> {
    if data.len() <= header_offset {
        return None;
    }

    let contact_count = data[header_offset] & 0x1F;

    // No contacts - return empty state with no buttons
    if contact_count == 0 {
        return Some(TouchpadState {
            contact_count: 0,
            buttons: 0,
            ..Default::default()
        });
    }

    // Validate contact count
    if contact_count > max_contacts.min(5) {
        return None;
    }

    let contact_size = 5;
    let contacts_start = header_offset + 1;
    let expected_len = contacts_start + (contact_count as usize * contact_size);

    if data.len() < expected_len {
        return None;
    }

    let mut state = TouchpadState::default();
    state.contact_count = contact_count;

    let mut valid_contacts = 0;
    let mut offset = contacts_start;

    for i in 0..(contact_count as usize).min(MAX_CONTACTS) {
        if offset + 5 > data.len() {
            break;
        }

        let flags = data[offset];
        let tip = (flags & 0x01) != 0;
        let confidence = (flags & 0x02) != 0;
        let contact_id = (flags >> 2) & 0x3F;

        let x = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as i32;
        let y = u16::from_le_bytes([data[offset + 3], data[offset + 4]]) as i32;

        let max_x = if logical_max_x > 0 { logical_max_x } else { 65535 };
        let max_y = if logical_max_y > 0 { logical_max_y } else { 65535 };
        if x < 0 || y < 0 || x > max_x || y > max_y {
            return None;
        }

        // Count any contact with tip set
        if tip {
            valid_contacts += 1;
        }

        state.contacts[i] = TouchPoint {
            id: contact_id,
            x,
            y,
            tip,
            // Require BOTH tip AND confidence for full pressure
            // This filters out ghost touches that only have tip set
            pressure: if tip && confidence { 200 } else if confidence { 150 } else if tip { 50 } else { 0 },
            width: 0,
            height: 0,
        };

        offset += contact_size;
    }

    // Must have at least one valid contact if contact_count > 0
    if contact_count > 0 && valid_contacts == 0 {
        // All contacts invalid - treat as no contact
        state.contact_count = 0;
    }

    // Read button byte - only if we have a valid parse
    // NEVER read buttons for invalid parses to avoid ghost clicks
    if offset < data.len() && valid_contacts > 0 {
        // Only accept button if the value looks reasonable (0, 1, 2, or 3)
        let btn = data[offset] & 0x03;
        state.buttons = btn;
    } else {
        state.buttons = 0;
    }

    Some(state)
}

pub(crate) fn try_parse_precision_touchpad(
    data: &[u8],
    state: &mut TouchpadState,
    max_contacts: u8,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    // Standard precision touchpad without scan time
    if data.len() < 6 {
        return false;
    }

    let contact_count = data[0] & 0x1F;

    if contact_count == 0 {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }

    if contact_count > max_contacts.min(5) {
        return false;
    }

    let contact_size = 5;
    let expected_len = 1 + (contact_count as usize * contact_size);
    if data.len() < expected_len {
        return false;
    }

    state.contact_count = contact_count;

    let mut offset = 1;
    let mut valid_count = 0;

    for i in 0..(contact_count as usize).min(MAX_CONTACTS) {
        if offset + 5 > data.len() {
            break;
        }

        let flags = data[offset];
        let tip = (flags & 0x01) != 0;
        let confidence = (flags & 0x02) != 0;
        let contact_id = (flags >> 2) & 0x3F;

        let x = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as i32;
        let y = u16::from_le_bytes([data[offset + 3], data[offset + 4]]) as i32;

        let max_x = if logical_max_x > 0 { logical_max_x } else { 65535 };
        let max_y = if logical_max_y > 0 { logical_max_y } else { 65535 };
        if x < 0 || y < 0 || x > max_x || y > max_y {
            return false;
        }

        if tip {
            valid_count += 1;
        }

        state.contacts[i] = TouchPoint {
            id: contact_id,
            x,
            y,
            tip,
            pressure: if tip && confidence { 200 } else if tip { 100 } else { 0 },
            width: 0,
            height: 0,
        };

        offset += contact_size;
    }

    if contact_count > 0 && valid_count == 0 {
        state.contact_count = 0;
    }

    if offset < data.len() && valid_count > 0 {
        state.buttons = data[offset] & 0x03;
    } else {
        state.buttons = 0;
    }

    true
}

pub(crate) fn try_parse_windows_precision(
    data: &[u8],
    state: &mut TouchpadState,
    max_contacts: u8,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    // Windows Precision Touchpad with button byte at position 1
    if data.len() < 9 {
        return false;
    }

    let contact_count = data[0] & 0x1F;

    if contact_count == 0 {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }

    if contact_count > max_contacts.min(5) {
        return false;
    }

    state.contact_count = contact_count;

    let mut offset = 2;
    let mut valid_count = 0;

    for i in 0..(contact_count as usize).min(MAX_CONTACTS) {
        if offset + 7 > data.len() {
            break;
        }

        let flags = data[offset];
        let tip = (flags & 0x01) != 0;
        let confidence = (flags & 0x02) != 0;
        let contact_id = (flags >> 2) & 0x3F;

        let x = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as i32;
        let y = u16::from_le_bytes([data[offset + 3], data[offset + 4]]) as i32;
        let pressure = data[offset + 5];
        let width = data[offset + 6];

        let max_x = if logical_max_x > 0 { logical_max_x } else { 65535 };
        let max_y = if logical_max_y > 0 { logical_max_y } else { 65535 };
        if x < 0 || y < 0 || x > max_x || y > max_y {
            return false;
        }

        if tip {
            valid_count += 1;
        }

        state.contacts[i] = TouchPoint {
            id: contact_id,
            x,
            y,
            tip,
            pressure: if tip && confidence { pressure.max(100) } else if tip { pressure.max(50) } else { 0 },
            width,
            height: width,
        };

        offset += 7;
    }

    if contact_count > 0 && valid_count == 0 {
        state.contact_count = 0;
    }

    if valid_count > 0 {
        state.buttons = data[1] & 0x03;
    } else {
        state.buttons = 0;
    }

    true
}

pub(crate) fn try_parse_synaptics(data: &[u8], state: &mut TouchpadState) -> bool {
    if data.len() < 8 {
        return false;
    }

    let packet_type = data[0] & 0xC0;
    if packet_type != 0x80 && packet_type != 0xC0 {
        return false;
    }

    let finger_count = ((data[0] >> 4) & 0x03) + 1;
    state.contact_count = finger_count as u8;

    let x1 = ((data[1] as i32) << 4) | ((data[3] as i32) & 0x0F);
    let y1 = ((data[2] as i32) << 4) | ((data[3] as i32) >> 4);
    let pressure1 = data[4];

    // Only set buttons from physical button press, not from pressure
    state.buttons = data[0] & 0x03;

    state.contacts[0] = TouchPoint {
        id: 0,
        x: x1,
        y: y1,
        tip: pressure1 > 30,
        pressure: pressure1,
        width: (data[5] & 0x0F) * 2,
        height: (data[5] >> 4) * 2,
    };

    if finger_count >= 2 && data.len() >= 12 {
        let x2 = ((data[6] as i32) << 4) | ((data[8] as i32) & 0x0F);
        let y2 = ((data[7] as i32) << 4) | ((data[8] as i32) >> 4);
        let pressure2 = data[9];

        state.contacts[1] = TouchPoint {
            id: 1,
            x: x2,
            y: y2,
            tip: pressure2 > 30,
            pressure: pressure2,
            width: 0,
            height: 0,
        };
    }

    true
}

pub(crate) fn try_parse_elan(data: &[u8], state: &mut TouchpadState) -> bool {
    if data.len() < 6 {
        return false;
    }

    // ELAN header check
    if data[0] != 0x04 && data[0] != 0x0D {
        return false;
    }

    let fingers = data[1] & 0x0F;
    if fingers == 0 {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }

    if fingers > 5 {
        return false;
    }

    state.contact_count = fingers as u8;
    state.buttons = (data[1] >> 4) & 0x03;

    let mut offset = 2;
    for i in 0..(fingers as usize).min(MAX_CONTACTS) {
        if offset + 4 > data.len() {
            break;
        }

        let x = u16::from_le_bytes([data[offset], data[offset + 1]]) as i32;
        let y = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as i32;
        let pressure = if offset + 4 < data.len() { data[offset + 4] } else { 128 };

        state.contacts[i] = TouchPoint {
            id: i as u8,
            x,
            y,
            tip: pressure > 30,
            pressure,
            width: 0,
            height: 0,
        };

        offset += 5;
    }

    true
}

pub(crate) fn try_parse_standard_touchpad(
    data: &[u8],
    state: &mut TouchpadState,
    logical_max_x: i32,
    logical_max_y: i32,
) -> bool {
    if data.len() < 5 {
        return false;
    }

    let tip = (data[0] & 0x01) != 0;
    let confidence = (data[0] & 0x02) != 0;

    let x = u16::from_le_bytes([data[1], data[2]]) as i32;
    let y = u16::from_le_bytes([data[3], data[4]]) as i32;

    let max_x = if logical_max_x > 0 { logical_max_x } else { 65535 };
    let max_y = if logical_max_y > 0 { logical_max_y } else { 65535 };
    if x < 0 || y < 0 || x > max_x || y > max_y {
        return false;
    }

    if !tip {
        state.contact_count = 0;
        state.buttons = 0;
        return true;
    }

    state.contact_count = 1;
    state.contacts[0] = TouchPoint {
        id: 0,
        x,
        y,
        tip,
        pressure: if confidence { 200 } else { 100 },
        width: 0,
        height: 0,
    };

    // Only read button if we have valid contact
    if data.len() > 5 && tip {
        state.buttons = data[5] & 0x03;
    } else {
        state.buttons = 0;
    }

    true
}

// REMOVED: try_parse_mouse_report - touchpads should NEVER be parsed as mouse
// Mouse reports are relative movement, touchpads are absolute positioning
// Parsing touchpad data as mouse causes garbage movement and random button presses

pub(crate) fn parse_buttons(data: &[u8], offset: usize) -> u8 {
    if offset < data.len() {
        data[offset] & 0x03
    } else {
        0
    }
}

pub(crate) fn parse_contact_point(data: &[u8], offset: usize) -> Option<TouchPoint> {
    if offset + 5 > data.len() {
        return None;
    }

    let flags = data[offset];
    let tip = (flags & 0x01) != 0;
    let confidence = (flags & 0x02) != 0;
    let contact_id = (flags >> 2) & 0x3F;

    let x = u16::from_le_bytes([data[offset + 1], data[offset + 2]]) as i32;
    let y = u16::from_le_bytes([data[offset + 3], data[offset + 4]]) as i32;

    Some(TouchPoint {
        id: contact_id,
        x,
        y,
        tip,
        pressure: if tip && confidence { 200 } else if tip { 50 } else { 0 },
        width: 0,
        height: 0,
    })
}
