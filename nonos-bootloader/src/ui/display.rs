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
    pub(super) system_table: &'a mut SystemTable<uefi::table::Boot>,
    pub(super) theme: Theme,
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

    #[inline]
    pub(super) fn color_internal(&mut self, fg: Color, bg: Color) -> Result<(), Status> {
        match self.system_table.stdout().set_color(fg, bg) {
            Ok(()) => Ok(()),
            Err(_) => Err(Status::DEVICE_ERROR),
        }
    }

    #[inline]
    pub(super) fn raw(&mut self, s: &str) -> Result<(), Status> {
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
    pub(super) fn raw_char(&mut self, c: char) -> Result<(), Status> {
        let mut buf = [0u8; 4];
        let s = c.encode_utf8(&mut buf);
        self.raw(s)
    }

    #[inline]
    pub(super) fn line(&mut self, s: &str) -> Result<(), Status> {
        self.raw(s)?;
        self.raw("\r\n")
    }

    pub(super) fn level(&mut self, fg: Color, tag: &str, msg: &str) -> Result<(), Status> {
        self.color_internal(fg, self.theme.bg)?;
        self.raw(tag)?;
        self.color_internal(self.theme.text, self.theme.bg)?;
        self.line(msg)
    }

    pub(super) fn rule(&mut self, n: usize) -> Result<(), Status> {
        const DASH: &str = "─";
        for _ in 0..n {
            self.raw(DASH)?;
        }
        self.line("")
    }
}
