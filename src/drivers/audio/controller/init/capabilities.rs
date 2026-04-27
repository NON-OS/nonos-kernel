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

use super::super::super::constants::*;
use super::super::helpers::RegisterAccess;
use super::types::Capabilities;

pub(super) fn read_capabilities<T: RegisterAccess>(ctrl: &T) -> Capabilities {
    let gcap = ctrl.read_reg16(GCAP);
    Capabilities::from_gcap(gcap)
}

pub(super) fn read_codec_mask<T: RegisterAccess>(ctrl: &T) -> u16 {
    ctrl.read_reg16(STATESTS)
}

pub(super) fn find_primary_codec(codec_mask: u16) -> Option<u8> {
    (0..=15).find(|c| (codec_mask & (1 << c)) != 0).map(|c| c as u8)
}
