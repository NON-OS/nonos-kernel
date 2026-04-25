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

#[derive(Debug, Clone)]
pub struct AnimationState {
    pub start_ms: u64,
    pub duration_ms: u64,
    pub property: AnimatedProperty,
}

#[derive(Debug, Clone, Copy)]
pub enum AnimatedProperty {
    Opacity { from: u8, to: u8 },
    TranslateX { from: i32, to: i32 },
    TranslateY { from: i32, to: i32 },
}

impl AnimationState {
    pub fn new(start_ms: u64, duration_ms: u64, property: AnimatedProperty) -> Self {
        Self { start_ms, duration_ms, property }
    }

    pub fn progress(&self, now_ms: u64) -> u8 {
        if now_ms <= self.start_ms {
            return 0;
        }
        let elapsed = now_ms - self.start_ms;
        if elapsed >= self.duration_ms {
            return 255;
        }
        ((elapsed * 255) / self.duration_ms) as u8
    }

    pub fn is_complete(&self, now_ms: u64) -> bool {
        now_ms >= self.start_ms + self.duration_ms
    }

    pub fn current_value(&self, now_ms: u64) -> AnimatedProperty {
        let p = self.progress(now_ms) as i32;
        match self.property {
            AnimatedProperty::Opacity { from, to } => {
                let v = from as i32 + ((to as i32 - from as i32) * p) / 255;
                AnimatedProperty::Opacity { from: v as u8, to: v as u8 }
            }
            AnimatedProperty::TranslateX { from, to } => {
                let v = from + ((to - from) * p) / 255;
                AnimatedProperty::TranslateX { from: v, to: v }
            }
            AnimatedProperty::TranslateY { from, to } => {
                let v = from + ((to - from) * p) / 255;
                AnimatedProperty::TranslateY { from: v, to: v }
            }
        }
    }
}
