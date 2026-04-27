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

use crate::display::{log_hash, log_hex, log_ok, show_handoff_message};
use crate::loader::KernelImage;

pub fn show_handoff_status(rng_seed: &[u8; 32]) {
    log_ok(b"Entropy collected");
    log_hash(b"RNGseed ", rng_seed);
    log_ok(b"CryptoHandoff prepared");
    log_ok(b"FirmwareHandoff prepared");
}

pub fn show_completion_status(kernel_image: &KernelImage) {
    log_ok(b"All boot stages COMPLETE");
    log_hex(b"jumping ", kernel_image.entry_point as u64);
    show_handoff_message();
}
