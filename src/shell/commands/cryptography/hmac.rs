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

use crate::shell::output::print_line;
use crate::graphics::framebuffer::{COLOR_TEXT_DIM, COLOR_TEXT_WHITE, COLOR_YELLOW};
use crate::shell::commands::utils::trim_bytes;

use super::util::{split_first_word, print_hash_hex};

pub fn cmd_hmac(cmd: &[u8]) {
    let args = if cmd.len() > 5 {
        trim_bytes(&cmd[5..])
    } else {
        print_line(b"Usage: hmac <key> <message>", COLOR_TEXT_DIM);
        print_line(b"Computes HMAC-SHA256", COLOR_TEXT_DIM);
        return;
    };

    let (key, message) = split_first_word(args);

    if key.is_empty() || message.is_empty() {
        print_line(b"hmac: key and message required", COLOR_YELLOW);
        return;
    }

    use crate::crypto::util::hmac::hmac_sha256;
    let mac = hmac_sha256(key, message);

    print_line(b"HMAC-SHA256:", COLOR_TEXT_WHITE);
    print_hash_hex(&mac);
}
