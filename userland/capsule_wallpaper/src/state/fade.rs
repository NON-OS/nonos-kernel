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

// Linear alpha ramp between two endpoints. `from_ns`/`to_ns` are
// monotonic-clock samples taken at fade start; the runner queries
// `sample` each pacer tick to read the interpolated alpha and
// detect completion.

pub struct FadeTimeline {
    from_alpha: u8,
    to_alpha: u8,
    from_ns: u64,
    to_ns: u64,
    active: bool,
}

impl FadeTimeline {
    pub const fn new() -> Self {
        Self { from_alpha: 0xFF, to_alpha: 0xFF, from_ns: 0, to_ns: 0, active: false }
    }

    pub fn start(&mut self, from: u8, to: u8, now_ns: u64, duration_ns: u64) {
        if duration_ns == 0 || from == to {
            self.from_alpha = to;
            self.to_alpha = to;
            self.active = false;
            return;
        }
        self.from_alpha = from;
        self.to_alpha = to;
        self.from_ns = now_ns;
        self.to_ns = now_ns.saturating_add(duration_ns);
        self.active = true;
    }

    pub fn active(&self) -> bool {
        self.active
    }

    pub fn sample(&mut self, now_ns: u64) -> u8 {
        if !self.active {
            return self.to_alpha;
        }
        if now_ns >= self.to_ns {
            self.active = false;
            return self.to_alpha;
        }
        let span = self.to_ns - self.from_ns;
        let elapsed = now_ns - self.from_ns;
        let from = self.from_alpha as i64;
        let to = self.to_alpha as i64;
        let v = from + ((to - from) * elapsed as i64) / span as i64;
        v.clamp(0, 255) as u8
    }
}
