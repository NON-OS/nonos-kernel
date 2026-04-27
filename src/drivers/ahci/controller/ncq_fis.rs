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

use super::super::constants::FIS_TYPE_REG_H2D;

pub(super) fn fill_fpdma_fis(
    cfis: &mut [u8],
    cmd: u8,
    lba: u64,
    count: u16,
    tag: u8,
    _is_write: bool,
) {
    for b in cfis.iter_mut() {
        *b = 0;
    }
    cfis[0] = FIS_TYPE_REG_H2D;
    cfis[1] = 1 << 7;
    cfis[2] = cmd;
    cfis[3] = (count & 0xFF) as u8;
    cfis[4] = (lba & 0xFF) as u8;
    cfis[5] = ((lba >> 8) & 0xFF) as u8;
    cfis[6] = ((lba >> 16) & 0xFF) as u8;
    cfis[7] = 0x40;
    cfis[8] = ((lba >> 24) & 0xFF) as u8;
    cfis[9] = ((lba >> 32) & 0xFF) as u8;
    cfis[10] = ((lba >> 40) & 0xFF) as u8;
    cfis[11] = ((count >> 8) & 0xFF) as u8;
    cfis[12] = tag << 3;
    cfis[13] = 0;
    cfis[14] = 0;
    cfis[15] = 0;
}
