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

use crate::display::framebuffer::{COLOR_ACCENT, COLOR_GREEN, COLOR_RED, COLOR_WHITE};
use crate::shell::output::print_line;

pub fn try_dispatch_script(cmd: &[u8]) -> bool {
    let s = core::str::from_utf8(cmd).unwrap_or("");
    if s.starts_with("run ") {
        let path = s[4..].trim();
        run_script(path);
        return true;
    }
    if s.starts_with("noxs ") || s == "noxs" {
        if s.len() > 5 {
            eval_inline(&s[5..]);
        } else {
            repl();
        }
        return true;
    }
    false
}

fn run_script(path: &str) {
    match crate::fs::ramfs::read_file(path) {
        Ok(data) => {
            let code = core::str::from_utf8(&data).unwrap_or("");
            let mut script = crate::lang::NoxScript::new();
            match script.eval(code) {
                Ok(_) => print_line(b"Script completed", COLOR_GREEN),
                Err(e) => print_line(alloc::format!("Error: {}", e).as_bytes(), COLOR_RED),
            }
        }
        Err(_) => print_line(b"File not found", COLOR_RED),
    }
}

fn eval_inline(code: &str) {
    let mut script = crate::lang::NoxScript::new();
    match script.eval(code) {
        Ok(v) => match v {
            crate::lang::script::Value::Int(i) => {
                print_line(alloc::format!("{}", i).as_bytes(), COLOR_WHITE)
            }
            crate::lang::script::Value::Str(s) => print_line(s.as_bytes(), COLOR_WHITE),
            _ => {}
        },
        Err(e) => print_line(alloc::format!("Error: {}", e).as_bytes(), COLOR_RED),
    }
}

fn repl() {
    print_line(b"NOXScript REPL - Type 'exit' to quit", COLOR_ACCENT);
    print_line(b"Example: let x = 5", COLOR_WHITE);
    print_line(b"         print x + 3", COLOR_WHITE);
}
