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

use super::field_location::FieldLocation;

#[derive(Debug, Clone, Copy, Default)]
pub struct ContactFields {
    pub tip_switch: FieldLocation,
    pub confidence: FieldLocation,
    pub contact_id: FieldLocation,
    pub x: FieldLocation,
    pub y: FieldLocation,
    pub pressure: FieldLocation,
    pub width: FieldLocation,
    pub height: FieldLocation,
}

#[derive(Debug, Clone, Default)]
pub struct TouchpadLayout {
    pub report_id: u8,
    pub scan_time: FieldLocation,
    pub contact_count: FieldLocation,
    pub button: FieldLocation,
    pub contacts: [ContactFields; 5],
    pub contact_field_size: u16,
    pub total_report_size: u16,
}

#[derive(Debug, Clone)]
pub struct ReportInfo {
    pub report_id: u8,
    pub size: u16,
}
