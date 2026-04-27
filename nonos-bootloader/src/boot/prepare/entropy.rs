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

use uefi::prelude::*;

use crate::display::{log_error as panel_error, show_error_screen};
use crate::entropy::collect_boot_entropy_64;
use crate::log::logger::log_error;

use super::super::util::fatal_reset;

pub fn collect_entropy(st: &mut SystemTable<Boot>, gop: bool) -> [u8; 32] {
    let entropy = match collect_boot_entropy_64(st) {
        Ok(e) => e,
        Err(msg) => {
            log_error("entropy", msg);
            if gop {
                panel_error(b"Entropy collection failed");
                show_error_screen(b"Insufficient entropy for secure boot");
            }
            fatal_reset(st, "entropy collection failed");
        }
    };
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&entropy[..32]);
    rng_seed
}
