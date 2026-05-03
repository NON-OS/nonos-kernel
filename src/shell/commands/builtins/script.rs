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
use crate::shell::script;
use crate::display::framebuffer::{COLOR_TEXT_DIM, COLOR_RED, COLOR_GREEN};
use crate::shell::commands::utils::{trim_bytes, starts_with};

pub fn cmd_nosh(cmd: &[u8]) {
    let args = if cmd.len() > 5 { trim_bytes(&cmd[5..]) } else {
        print_line(b"NOSH - NONOS Shell Script", COLOR_GREEN);
        print_line(b"Usage: nosh <file> | nosh -c \"script\"", COLOR_TEXT_DIM);
        print_line(b"", COLOR_TEXT_DIM);
        print_line(b"Syntax:", COLOR_GREEN);
        print_line(b"  if $x == 1 then ... else ... fi", COLOR_TEXT_DIM);
        print_line(b"  for i in 1 2 3 do ... done", COLOR_TEXT_DIM);
        print_line(b"  while $x < 10 do ... done", COLOR_TEXT_DIM);
        print_line(b"  x = 42", COLOR_TEXT_DIM);
        return;
    };

    if starts_with(args, b"-c ") {
        let code = trim_bytes(&args[3..]);
        if let Ok(src) = core::str::from_utf8(code) {
            script::run_script(src);
        }
    } else {
        let path = core::str::from_utf8(args).unwrap_or("");
        match crate::fs::read_file(path) {
            Ok(data) => {
                if let Ok(src) = core::str::from_utf8(&data) {
                    script::run_script(src);
                } else {
                    print_line(b"nosh: invalid UTF-8 in script", COLOR_RED);
                }
            }
            Err(_) => {
                print_line(b"nosh: file not found", COLOR_RED);
            }
        }
    }
}
