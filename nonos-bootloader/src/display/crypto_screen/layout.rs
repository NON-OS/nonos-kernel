// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::gop::get_dimensions;

const MARGIN: u32 = 30;
const HEADER_H: u32 = 32;
const PAD: u32 = 16;

pub const LOG_X: u32 = 40;
pub const LOG_Y: u32 = 100;
pub const LOG_W: u32 = 420;
pub const CRYPTO_X: u32 = 500;
pub const CRYPTO_Y: u32 = 100;

pub fn get_crypto_panel_x() -> u32 {
    let (screen_w, _) = get_dimensions();
    (screen_w / 2) + (MARGIN / 2) + PAD
}

pub fn init_crypto_screen() {}
