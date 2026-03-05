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
use uefi::proto::console::text::Color;
use uefi::CStr16;

use super::theme::Theme;

pub struct Ui<'a> {
    system_table: &'a mut SystemTable<uefi::table::Boot>,
    theme: Theme,
}

impl<'a> Ui<'a> {
    pub fn new(st: &'a mut SystemTable<uefi::table::Boot>) -> Self {
        Ui {
            system_table: st,
            theme: Theme::default(),
        }
    }

    pub fn set_theme(&mut self, t: Theme) {
        self.theme = t;
    }

    pub fn theme(&self) -> &Theme {
        &self.theme
    }

    pub fn banner(&mut self) -> Result<(), Status> {
        self.color(self.theme.title, self.theme.bg)?;
        match self.system_table.stdout().clear() {
            Ok(()) => {}
            Err(_) => return Err(Status::DEVICE_ERROR),
        }
        self.line("")?;
        self.raw("              ╔═════════════════════════════════════════════════════════════╗")?;
        self.raw("              ║                 NØNOS :: ZERO-STATE LAUNCHPAD               ║")?;
        self.raw("              ║         Privacy-Native / Identity-Free / Capsule-First      ║")?;
        self.raw("              ║        UEFI Boot  →  Verified Capsule  →  Kernel Jump       ║")?;
        self.raw("              ╚═════════════════════════════════════════════════════════════╝")?;
        self.line("")?;
        self.color(self.theme.text, self.theme.bg)
    }

    pub fn section(&mut self, title: &str) -> Result<(), Status> {
        self.color(self.theme.title, self.theme.bg)?;
        self.raw("── ")?;
        self.raw(title)?;
        self.raw(" ")?;
        self.rule(60)?;
        self.color(self.theme.text, self.theme.bg)
    }

    pub fn kv(&mut self, key: &str, val: &str) -> Result<(), Status> {
        self.color(self.theme.info, self.theme.bg)?;
        self.raw("• ")?;
        self.raw(key)?;
        self.raw(": ")?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(val)
    }

    pub fn info(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.info, "[info] ", msg)
    }

    pub fn ok(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.ok, "[ ok ] ", msg)
    }

    pub fn warn(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.warn, "[warn] ", msg)
    }

    pub fn fail(&mut self, msg: &str) -> Result<(), Status> {
        self.level(self.theme.err, "[FAIL] ", msg)
    }

    pub fn panic_block(&mut self, msg: &str) -> Result<(), Status> {
        self.color(self.theme.err, self.theme.bg)?;
        self.line("")?;
        self.raw("──────────────────── SYSTEM FAULT DETECTED ────────────────────")?;
        self.line("")?;
        self.raw("[!] ")?;
        self.line(msg)?;
        self.raw("───────────────────────────────────────────────────────────────")?;
        self.line("")?;
        self.color(self.theme.text, self.theme.bg)
    }

    pub fn progress(&mut self, current: usize, total: usize, label: &str) -> Result<(), Status> {
        let total = total.max(1);
        let width = 32usize;
        let filled = ((current.min(total) * width) / total).min(width);
        let mut bar = [b' '; 32];
        for item in bar.iter_mut().take(filled) {
            *item = b'=';
        }
        self.color(self.theme.info, self.theme.bg)?;
        self.raw("[")?;
        self.raw(core::str::from_utf8(&bar).unwrap_or("                                "))?;
        self.raw("] ")?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(label)
    }

    pub fn spinner(&mut self, i: usize, label: &str) -> Result<(), Status> {
        const FR: &[u8] = b"|/-\\";
        let ch = FR[i % FR.len()];
        self.color(self.theme.info, self.theme.bg)?;
        self.raw("[")?;
        self.raw_char(ch as char)?;
        self.raw("] ")?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(label)
    }

    #[inline]
    fn color(&mut self, fg: Color, bg: Color) -> Result<(), Status> {
        match self.system_table.stdout().set_color(fg, bg) {
            Ok(()) => Ok(()),
            Err(_) => Err(Status::DEVICE_ERROR),
        }
    }

    #[inline]
    fn raw(&mut self, s: &str) -> Result<(), Status> {
        let mut buffer = [0u16; 256];
        match CStr16::from_str_with_buf(s, &mut buffer) {
            Ok(uefi_str) => match self.system_table.stdout().output_string(uefi_str) {
                Ok(()) => Ok(()),
                Err(_) => Err(Status::DEVICE_ERROR),
            },
            Err(_) => Err(Status::INVALID_PARAMETER),
        }
    }

    #[inline]
    fn raw_char(&mut self, c: char) -> Result<(), Status> {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        self.raw(s)
    }

    #[inline]
    fn line(&mut self, s: &str) -> Result<(), Status> {
        self.raw(s)?;
        self.raw("\r\n")
    }

    fn level(&mut self, fg: Color, tag: &str, msg: &str) -> Result<(), Status> {
        self.color(fg, self.theme.bg)?;
        self.raw(tag)?;
        self.color(self.theme.text, self.theme.bg)?;
        self.line(msg)
    }

    fn rule(&mut self, n: usize) -> Result<(), Status> {
        const DASH: &str = "─";
        for _ in 0..n {
            self.raw(DASH)?;
        }
        self.line("")
    }
}
