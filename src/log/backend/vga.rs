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

use core::sync::atomic::Ordering;
use crate::arch::x86_64::vga::Color;
use crate::log::types::LogEntry;
use crate::log::manager::PANIC_MODE;
use super::traits::LogBackend;

pub struct VgaBackend;

impl LogBackend for VgaBackend {
    fn write(&mut self, entry: &LogEntry) {
        let is_panic = PANIC_MODE.load(Ordering::SeqCst);
        crate::arch::x86_64::vga::set_color(entry.sev.color(), Color::Black);
        let line = format_args!(
            "[{}][CPU{}][{:>5}] {}
",
            entry.ts, entry.cpu, entry.sev.as_str(), entry.msg
        );
        if is_panic {
            crate::arch::x86_64::vga::print_critical(&alloc::format!("{}", line));
        } else {
            crate::arch::x86_64::vga::print(&alloc::format!("{}", line));
        }
        crate::arch::x86_64::vga::set_color(Color::LightGray, Color::Black);
    }
}
