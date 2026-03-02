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
use crate::shell::commands::utils::{trim_bytes, format_num_simple};
use crate::graphics::framebuffer::{COLOR_TEXT, COLOR_TEXT_DIM, COLOR_RED};
use crate::fs::ramfs;
use super::utils::{bytes_to_str, hex_char};

pub fn cmd_xxd(cmd: &[u8]) {
    let path = if cmd.len() > 4 {
        trim_bytes(&cmd[4..])
    } else {
        print_line(b"Usage: xxd <file>", COLOR_TEXT_DIM);
        print_line(b"Display file contents in hex format", COLOR_TEXT_DIM);
        return;
    };

    let path_str = match bytes_to_str(path) {
        Some(s) => s,
        None => {
            print_line(b"xxd: invalid path encoding", COLOR_RED);
            return;
        }
    };

    match ramfs::read_file(path_str) {
        Ok(data) => {
            let max_lines = 32;
            let mut lines_shown = 0;

            for (offset, chunk) in data.chunks(16).enumerate() {
                if lines_shown >= max_lines {
                    let remaining = data.len() / 16 - lines_shown;
                    if remaining > 0 {
                        let mut line = [0u8; 40];
                        line[..4].copy_from_slice(b"... ");
                        let num_len = format_num_simple(&mut line[4..], remaining);
                        line[4+num_len..4+num_len+16].copy_from_slice(b" more lines ...");
                        print_line(&line[..20+num_len], COLOR_TEXT_DIM);
                    }
                    break;
                }

                let mut line = [0u8; 80];
                let addr = offset * 16;

                line[0] = hex_char((addr >> 12) as u8 & 0xf);
                line[1] = hex_char((addr >> 8) as u8 & 0xf);
                line[2] = hex_char((addr >> 4) as u8 & 0xf);
                line[3] = hex_char(addr as u8 & 0xf);
                line[4] = b':';
                line[5] = b' ';

                let mut pos = 6;
                for (i, &byte) in chunk.iter().enumerate() {
                    line[pos] = hex_char(byte >> 4);
                    line[pos + 1] = hex_char(byte & 0xf);
                    pos += 2;
                    if i % 2 == 1 {
                        line[pos] = b' ';
                        pos += 1;
                    }
                }

                for _ in chunk.len()..16 {
                    line[pos] = b' ';
                    line[pos + 1] = b' ';
                    pos += 2;
                    if chunk.len() % 2 == 0 {
                        line[pos] = b' ';
                        pos += 1;
                    }
                }

                line[pos] = b' ';
                pos += 1;

                for &byte in chunk {
                    line[pos] = if byte >= 0x20 && byte < 0x7f { byte } else { b'.' };
                    pos += 1;
                }

                print_line(&line[..pos], COLOR_TEXT);
                lines_shown += 1;
            }
        }
        Err(e) => {
            let mut line = [0u8; 80];
            line[..5].copy_from_slice(b"xxd: ");
            let err_str = e.as_str().as_bytes();
            let err_len = err_str.len().min(60);
            line[5..5+err_len].copy_from_slice(&err_str[..err_len]);
            print_line(&line[..5+err_len], COLOR_RED);
        }
    }
}
