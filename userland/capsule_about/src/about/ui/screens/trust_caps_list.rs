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

use crate::about::data::caps::ALL_CAPS;
use crate::about::format::{hex_u64, u64_decimal};

use super::super::card;
use super::super::kv::ROW_H;
use super::tile_text::push;
use super::trust_pills;

pub const CAP_SLOTS: usize = ALL_CAPS.len();
pub const ROLE_GAP: u32 = 12;
pub const DENIED_GAP: u32 = 14;

// The grid is driven off the descriptor table, never off a list typed here, so a
// capability added to the kernel's mask appears on the correct side by itself.
// `mask` is the word the kernel recorded for this window.
pub fn names(dst: &mut [&'static [u8]; CAP_SLOTS], mask: u64, granted: bool) -> usize {
    let mut n = 0usize;
    for cap in ALL_CAPS {
        if (mask & cap.bit != 0) == granted && n < dst.len() {
            dst[n] = cap.name;
            n += 1;
        }
    }
    n
}

// "Granted 6 of 22   mask 0x80001819", assembled from the table's own arithmetic
// so the count and the mask cannot drift apart.
pub fn summary<'a>(dst: &'a mut [u8; 48], mask: u64, granted: bool, show: bool) -> &'a [u8] {
    let mut slots: [&'static [u8]; CAP_SLOTS] = [b""; CAP_SLOTS];
    let count = names(&mut slots, mask, granted) as u64;
    let mut a = [0u8; 20];
    let mut b = [0u8; 20];
    let mut n = push(dst, 0, if granted { b"Granted " } else { b"Denied " });
    n = push(dst, n, u64_decimal(count, &mut a));
    n = push(dst, n, b" of ");
    n = push(dst, n, u64_decimal(ALL_CAPS.len() as u64, &mut b));
    if show {
        let mut hex = [0u8; 20];
        n = push(dst, n, b"    mask ");
        n = push(dst, n, hex_u64(mask, &mut hex));
    }
    &dst[..n]
}

// A table that did not answer leaves the card one line tall: the line that
// says so.
pub fn height(inner: u32, held: Option<u64>) -> u32 {
    let Some(mask) = held else {
        return card::OVERHEAD + ROW_H;
    };
    let mut slots: [&'static [u8]; CAP_SLOTS] = [b""; CAP_SLOTS];
    let granted = names(&mut slots, mask, true);
    let chips = trust_pills::height(&slots[..granted], inner);
    let denied = names(&mut slots, mask, false);
    let denied_chips = trust_pills::height(&slots[..denied], inner);
    let roles = granted as u32 * ROW_H;
    card::OVERHEAD + ROW_H + chips + ROLE_GAP + roles + DENIED_GAP + ROW_H + denied_chips
}
