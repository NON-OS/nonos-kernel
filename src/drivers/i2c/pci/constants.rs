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

pub const INTEL_VENDOR_ID: u16 = 0x8086;

pub const LPSS_I2C_DEVICE_IDS: &[(u16, &str, u32)] = &[
    (0x9D60, "Sunrise Point-LP I2C #0", 120_000_000),
    (0x9D61, "Sunrise Point-LP I2C #1", 120_000_000),
    (0x9D62, "Sunrise Point-LP I2C #2", 120_000_000),
    (0x9D63, "Sunrise Point-LP I2C #3", 120_000_000),
    (0x9D64, "Sunrise Point-LP I2C #4", 120_000_000),
    (0x9D65, "Sunrise Point-LP I2C #5", 120_000_000),
    (0xA160, "Sunrise Point-H I2C #0", 120_000_000),
    (0xA161, "Sunrise Point-H I2C #1", 120_000_000),
    (0xA162, "Sunrise Point-H I2C #2", 120_000_000),
    (0xA163, "Sunrise Point-H I2C #3", 120_000_000),
    (0x9DE8, "Cannon Point-LP I2C #0", 120_000_000),
    (0x9DE9, "Cannon Point-LP I2C #1", 120_000_000),
    (0x9DEA, "Cannon Point-LP I2C #2", 120_000_000),
    (0x9DEB, "Cannon Point-LP I2C #3", 120_000_000),
    (0xA368, "Cannon Lake-H I2C #0", 120_000_000),
    (0xA369, "Cannon Lake-H I2C #1", 120_000_000),
    (0xA36A, "Cannon Lake-H I2C #2", 120_000_000),
    (0xA36B, "Cannon Lake-H I2C #3", 120_000_000),
    (0x02E8, "Comet Lake I2C #0", 120_000_000),
    (0x02E9, "Comet Lake I2C #1", 120_000_000),
    (0x02EA, "Comet Lake I2C #2", 120_000_000),
    (0x02EB, "Comet Lake I2C #3", 120_000_000),
    (0x06E8, "Comet Lake-H I2C #0", 120_000_000),
    (0x06E9, "Comet Lake-H I2C #1", 120_000_000),
    (0x06EA, "Comet Lake-H I2C #2", 120_000_000),
    (0x06EB, "Comet Lake-H I2C #3", 120_000_000),
    (0xA0E8, "Tiger Lake-LP I2C #0", 100_000_000),
    (0xA0E9, "Tiger Lake-LP I2C #1", 100_000_000),
    (0xA0EA, "Tiger Lake-LP I2C #2", 100_000_000),
    (0xA0EB, "Tiger Lake-LP I2C #3", 100_000_000),
    (0xA0C5, "Tiger Lake-LP I2C #4", 100_000_000),
    (0xA0C6, "Tiger Lake-LP I2C #5", 100_000_000),
    (0x43E8, "Tiger Lake-H I2C #0", 100_000_000),
    (0x43E9, "Tiger Lake-H I2C #1", 100_000_000),
    (0x43EA, "Tiger Lake-H I2C #2", 100_000_000),
    (0x43EB, "Tiger Lake-H I2C #3", 100_000_000),
    (0x51E8, "Alder Lake-P I2C #0", 100_000_000),
    (0x51E9, "Alder Lake-P I2C #1", 100_000_000),
    (0x51EA, "Alder Lake-P I2C #2", 100_000_000),
    (0x51EB, "Alder Lake-P I2C #3", 100_000_000),
    (0x51C5, "Alder Lake-P I2C #4", 100_000_000),
    (0x51C6, "Alder Lake-P I2C #5", 100_000_000),
    (0x7AE8, "Alder Lake-S I2C #0", 100_000_000),
    (0x7AE9, "Alder Lake-S I2C #1", 100_000_000),
    (0x7AEA, "Alder Lake-S I2C #2", 100_000_000),
    (0x7AEB, "Alder Lake-S I2C #3", 100_000_000),
    (0x7AF8, "Alder Lake-S I2C #4", 100_000_000),
    (0x7AF9, "Alder Lake-S I2C #5", 100_000_000),
    (0xA0D8, "Raptor Lake-P I2C #0", 100_000_000),
    (0xA0D9, "Raptor Lake-P I2C #1", 100_000_000),
    (0xA0DA, "Raptor Lake-P I2C #2", 100_000_000),
    (0xA0DB, "Raptor Lake-P I2C #3", 100_000_000),
    (0xA0DC, "Raptor Lake-P I2C #4", 100_000_000),
    (0xA0DD, "Raptor Lake-P I2C #5", 100_000_000),
    (0x7A4C, "Raptor Lake-S I2C #0", 100_000_000),
    (0x7A4D, "Raptor Lake-S I2C #1", 100_000_000),
    (0x7A4E, "Raptor Lake-S I2C #2", 100_000_000),
    (0x7A4F, "Raptor Lake-S I2C #3", 100_000_000),
    (0x7A7C, "Raptor Lake-S I2C #4", 100_000_000),
    (0x7A7D, "Raptor Lake-S I2C #5", 100_000_000),
    (0x54E8, "Alder Lake-N I2C #0", 100_000_000),
    (0x54E9, "Alder Lake-N I2C #1", 100_000_000),
    (0x54EA, "Alder Lake-N I2C #2", 100_000_000),
    (0x54EB, "Alder Lake-N I2C #3", 100_000_000),
    (0x7E50, "Meteor Lake-P I2C #0", 100_000_000),
    (0x7E51, "Meteor Lake-P I2C #1", 100_000_000),
    (0x7E52, "Meteor Lake-P I2C #2", 100_000_000),
    (0x7E78, "Meteor Lake-P I2C #3", 100_000_000),
    (0x7E79, "Meteor Lake-P I2C #4", 100_000_000),
    (0x7E7A, "Meteor Lake-P I2C #5", 100_000_000),
    (0x34E8, "Ice Lake-LP I2C #0", 100_000_000),
    (0x34E9, "Ice Lake-LP I2C #1", 100_000_000),
    (0x34EA, "Ice Lake-LP I2C #2", 100_000_000),
    (0x34EB, "Ice Lake-LP I2C #3", 100_000_000),
    (0x34C5, "Ice Lake-LP I2C #4", 100_000_000),
    (0x34C6, "Ice Lake-LP I2C #5", 100_000_000),
    (0x4DE8, "Jasper Lake I2C #0", 100_000_000),
    (0x4DE9, "Jasper Lake I2C #1", 100_000_000),
    (0x4DEA, "Jasper Lake I2C #2", 100_000_000),
    (0x4DEB, "Jasper Lake I2C #3", 100_000_000),
    (0x4DC5, "Jasper Lake I2C #4", 100_000_000),
    (0x4DC6, "Jasper Lake I2C #5", 100_000_000),
    (0x5AC2, "Broxton I2C #0", 100_000_000),
    (0x5AC4, "Broxton I2C #1", 100_000_000),
    (0x5AC6, "Broxton I2C #2", 100_000_000),
    (0x5AEE, "Broxton I2C #3", 100_000_000),
    (0x1AC2, "Broxton-P I2C #0", 100_000_000),
    (0x1AC4, "Broxton-P I2C #1", 100_000_000),
    (0x1AC6, "Broxton-P I2C #2", 100_000_000),
    (0x1AEE, "Broxton-P I2C #3", 100_000_000),
    (0x31AC, "Gemini Lake I2C #0", 100_000_000),
    (0x31AE, "Gemini Lake I2C #1", 100_000_000),
    (0x31B0, "Gemini Lake I2C #2", 100_000_000),
    (0x31B2, "Gemini Lake I2C #3", 100_000_000),
    (0x31B4, "Gemini Lake I2C #4", 100_000_000),
    (0x31B6, "Gemini Lake I2C #5", 100_000_000),
    (0x31B8, "Gemini Lake I2C #6", 100_000_000),
    (0x31BA, "Gemini Lake I2C #7", 100_000_000),
];

pub const KNOWN_TOUCHPAD_ADDRS: &[u8] = &[
    0x10, // ELAN alternate
    0x15, // ELAN (most common on HP laptops)
    0x2C, // Synaptics
    0x38, // FocalTech
    0x4B, // Synaptics alternate
    0x4C, // Synaptics alternate
    0x20, // Some Elan devices
    0x24, // Some multi-touch
];
