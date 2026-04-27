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

use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};
use crate::sdk::app::{App, AppContext, AppEvent, AppResult};

pub struct CounterApp {
    count: i32,
}

impl CounterApp {
    pub fn new() -> Self {
        Self { count: 0 }
    }
    fn txt(&self, x: u32, y: u32, t: &[u8], c: u32) {
        for (i, &ch) in t.iter().enumerate() {
            draw_char(x + i as u32 * 8, y, ch, c);
        }
    }
    fn fmt(&self, buf: &mut [u8; 12]) -> usize {
        let (neg, mut v) =
            if self.count < 0 { (true, (-self.count) as u32) } else { (false, self.count as u32) };
        if v == 0 {
            buf[0] = b'0';
            return 1;
        }
        let mut i = 0;
        while v > 0 {
            buf[11 - i] = b'0' + (v % 10) as u8;
            v /= 10;
            i += 1;
        }
        if neg {
            buf[11 - i] = b'-';
            i += 1;
        }
        buf.copy_within(12 - i.., 0);
        i
    }
}

impl App for CounterApp {
    fn id(&self) -> &str {
        "counter"
    }
    fn name(&self) -> &str {
        "Counter"
    }
    fn version(&self) -> &str {
        "1.0.0"
    }
    fn init(&mut self, _ctx: &AppContext) -> AppResult<()> {
        self.count = 0;
        Ok(())
    }

    fn render(&self, ctx: &AppContext) {
        fill_rect(ctx.x, ctx.y, ctx.width, ctx.height, 0xFF14141C);
        self.txt(ctx.x + 20, ctx.y + 20, b"Counter App", 0xFFFFFFFF);
        let mut buf = [0u8; 12];
        let len = self.fmt(&mut buf);
        self.txt(
            ctx.x + ctx.width / 2 - len as u32 * 4,
            ctx.y + ctx.height / 2,
            &buf[..len],
            0xFF00D4FF,
        );
        fill_rounded_rect(ctx.x + 20, ctx.y + ctx.height - 60, 80, 40, 8, 0xFF00E676);
        self.txt(ctx.x + 40, ctx.y + ctx.height - 48, b"+", 0xFF000000);
        fill_rounded_rect(ctx.x + 120, ctx.y + ctx.height - 60, 80, 40, 8, 0xFFEF5350);
        self.txt(ctx.x + 140, ctx.y + ctx.height - 48, b"-", 0xFF000000);
    }

    fn handle_event(&mut self, ctx: &AppContext, event: AppEvent) -> AppResult<bool> {
        if let AppEvent::Click(mx, my) = event {
            let rx = mx.saturating_sub(ctx.x);
            let ry = my.saturating_sub(ctx.y);
            if ry >= ctx.height - 60 && ry < ctx.height - 20 {
                if rx >= 20 && rx < 100 {
                    self.count += 1;
                    return Ok(true);
                }
                if rx >= 120 && rx < 200 {
                    self.count -= 1;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn cleanup(&mut self) {}
}
