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

use alloc::format;
use alloc::string::String;

pub struct Output;

impl Output {
    pub fn arrow(msg: &str) -> String {
        format!("==> {}", msg)
    }
    pub fn arrow_green(msg: &str) -> String {
        format!("\x1b[32m==>\x1b[0m \x1b[1m{}\x1b[0m", msg)
    }
    pub fn arrow_blue(msg: &str) -> String {
        format!("\x1b[34m==>\x1b[0m \x1b[1m{}\x1b[0m", msg)
    }
    pub fn arrow_yellow(msg: &str) -> String {
        format!("\x1b[33m==>\x1b[0m \x1b[1m{}\x1b[0m", msg)
    }
    pub fn arrow_red(msg: &str) -> String {
        format!("\x1b[31m==>\x1b[0m \x1b[1m{}\x1b[0m", msg)
    }
    pub fn check(msg: &str) -> String {
        format!("\x1b[32m✓\x1b[0m {}", msg)
    }
    pub fn cross(msg: &str) -> String {
        format!("\x1b[31m✗\x1b[0m {}", msg)
    }
    pub fn bullet(msg: &str) -> String {
        format!("  • {}", msg)
    }
    pub fn indent(msg: &str) -> String {
        format!("    {}", msg)
    }
    pub fn bold(msg: &str) -> String {
        format!("\x1b[1m{}\x1b[0m", msg)
    }
    pub fn dim(msg: &str) -> String {
        format!("\x1b[2m{}\x1b[0m", msg)
    }
    pub fn progress(current: usize, total: usize, msg: &str) -> String {
        let pct = if total > 0 { (current * 100) / total } else { 0 };
        format!("[{:3}%] {}", pct, msg)
    }
}
