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

use super::easing::Easing;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AnimationStatus {
    Idle,
    Running,
    Completed,
    Paused,
}

#[derive(Clone, Copy)]
pub struct Animation {
    pub start_value: f32,
    pub end_value: f32,
    pub duration_ms: u64,
    pub easing: Easing,
    pub started_at: u64,
    pub status: AnimationStatus,
    pub delay_ms: u64,
}

impl Animation {
    pub const fn new(start: f32, end: f32, duration_ms: u64, easing: Easing) -> Self {
        Self {
            start_value: start,
            end_value: end,
            duration_ms,
            easing,
            started_at: 0,
            status: AnimationStatus::Idle,
            delay_ms: 0,
        }
    }

    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = delay_ms;
        self
    }

    pub fn start(&mut self, current_time: u64) {
        self.started_at = current_time;
        self.status = AnimationStatus::Running;
    }

    pub fn progress(&self, current_time: u64) -> f32 {
        if self.status != AnimationStatus::Running {
            return if self.status == AnimationStatus::Completed { 1.0 } else { 0.0 };
        }
        let effective_start = self.started_at + self.delay_ms;
        if current_time < effective_start {
            return 0.0;
        }
        let elapsed = current_time - effective_start;
        if elapsed >= self.duration_ms {
            return 1.0;
        }
        elapsed as f32 / self.duration_ms as f32
    }

    pub fn current_value(&self, current_time: u64) -> f32 {
        let progress = self.progress(current_time);
        let eased = super::easing::apply_easing(progress, self.easing);
        super::easing::interpolate(self.start_value, self.end_value, eased)
    }

    pub fn is_complete(&self, current_time: u64) -> bool {
        self.status == AnimationStatus::Running && self.progress(current_time) >= 1.0
    }

    pub fn complete(&mut self) {
        self.status = AnimationStatus::Completed;
    }
    pub fn reset(&mut self) {
        self.status = AnimationStatus::Idle;
        self.started_at = 0;
    }
}

impl Default for Animation {
    fn default() -> Self {
        Self::new(0.0, 1.0, 300, Easing::EaseOut)
    }
}
