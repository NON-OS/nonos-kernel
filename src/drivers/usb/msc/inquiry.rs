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

use alloc::string::{String, ToString};

#[derive(Debug, Clone)]
pub struct InquiryResponse {
    pub device_type: u8,
    pub removable: bool,
    pub version: u8,
    pub vendor: String,
    pub product: String,
    pub revision: String,
}

impl InquiryResponse {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 36 {
            return None;
        }

        Some(Self {
            device_type: data[0] & 0x1F,
            removable: (data[1] & 0x80) != 0,
            version: data[2],
            vendor: String::from_utf8_lossy(&data[8..16]).trim().to_string(),
            product: String::from_utf8_lossy(&data[16..32]).trim().to_string(),
            revision: String::from_utf8_lossy(&data[32..36]).trim().to_string(),
        })
    }
}
