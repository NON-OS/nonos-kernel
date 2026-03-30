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

pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
pub const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
pub const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
pub const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1D, 0x0E];
pub const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1D, 0x23];
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
pub const OID_EKU_SERVER_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
pub const OID_EKU_CLIENT_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
pub const OID_EKU_OCSP_SIGNING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];
