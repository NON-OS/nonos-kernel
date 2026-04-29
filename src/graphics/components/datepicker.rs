// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_text;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};

#[derive(Clone, Copy)]
pub struct DatePicker {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub selected_day: u8,
}

static MONTHS: &[&[u8]] = &[
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

impl DatePicker {
    pub const fn new(year: u16, month: u8, day: u8) -> Self {
        Self { year, month, day, selected_day: day }
    }

    pub fn days_in_month(&self) -> u8 {
        match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if self.is_leap_year() => 29,
            2 => 28,
            _ => 30,
        }
    }

    fn is_leap_year(&self) -> bool {
        (self.year % 4 == 0 && self.year % 100 != 0) || (self.year % 400 == 0)
    }

    pub fn prev_month(&mut self) {
        if self.month == 1 {
            self.month = 12;
            self.year -= 1;
        } else {
            self.month -= 1;
        }
        self.selected_day = self.selected_day.min(self.days_in_month());
    }

    pub fn next_month(&mut self) {
        if self.month == 12 {
            self.month = 1;
            self.year += 1;
        } else {
            self.month += 1;
        }
        self.selected_day = self.selected_day.min(self.days_in_month());
    }

    pub fn draw(&self, x: u32, y: u32) {
        fill_rounded_rect(x, y, 224, 220, 8, BG_ELEVATED);
        fill_rect(x, y + 40, 224, 1, BORDER_SUBTLE);
        draw_text(x + 12, y + 12, b"<", TEXT_PRIMARY);
        let month_name = MONTHS.get((self.month - 1) as usize).copied().unwrap_or(b"???");
        draw_text(x + 60, y + 12, month_name, TEXT_PRIMARY);
        let mut year_buf = [0u8; 4];
        format_year(self.year, &mut year_buf);
        draw_text(x + 150, y + 12, &year_buf, TEXT_SECONDARY);
        draw_text(x + 200, y + 12, b">", TEXT_PRIMARY);
        let days = [b"Su", b"Mo", b"Tu", b"We", b"Th", b"Fr", b"Sa"];
        for (i, d) in days.iter().enumerate() {
            draw_text(x + 8 + i as u32 * 32, y + 50, *d, TEXT_DIM);
        }
        self.draw_days(x, y + 70);
    }

    fn draw_days(&self, x: u32, y: u32) {
        let days = self.days_in_month();
        let first_weekday = self.first_weekday();
        for d in 1..=days {
            let idx = (first_weekday + d - 1) as u32;
            let row = idx / 7;
            let col = idx % 7;
            let dx = x + 8 + col * 32;
            let dy = y + row * 24;
            if d == self.selected_day {
                fill_rounded_rect(dx - 2, dy - 2, 24, 20, 4, ACCENT);
                draw_day(dx, dy, d, 0xFF0C0C10);
            } else {
                draw_day(dx, dy, d, TEXT_PRIMARY);
            }
        }
    }

    fn first_weekday(&self) -> u8 {
        let y = self.year as i32;
        let m = self.month as i32;
        let d = 1i32;
        let t = [0i32, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
        let y_adj = if m < 3 { y - 1 } else { y };
        ((y_adj + y_adj / 4 - y_adj / 100 + y_adj / 400 + t[(m - 1) as usize] + d) % 7) as u8
    }
}

fn format_year(year: u16, buf: &mut [u8; 4]) {
    buf[0] = b'0' + ((year / 1000) % 10) as u8;
    buf[1] = b'0' + ((year / 100) % 10) as u8;
    buf[2] = b'0' + ((year / 10) % 10) as u8;
    buf[3] = b'0' + (year % 10) as u8;
}

fn draw_day(x: u32, y: u32, day: u8, color: u32) {
    let mut buf = [b' ', b' '];
    if day >= 10 {
        buf[0] = b'0' + day / 10;
    }
    buf[1] = b'0' + day % 10;
    draw_text(x, y, &buf, color);
}
