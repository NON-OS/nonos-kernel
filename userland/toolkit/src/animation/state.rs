use crate::animation::easing::{apply, Curve, UNIT};
use crate::animation::timing::DurationMs;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Animation {
    pub from: i32,
    pub to: i32,
    pub value: i32,
    pub elapsed_ms: u32,
    pub duration_ms: DurationMs,
    pub curve: Curve,
    pub active: bool,
}

impl Animation {
    pub const fn idle(value: i32) -> Self {
        Self {
            from: value,
            to: value,
            value,
            elapsed_ms: 0,
            duration_ms: DurationMs(1),
            curve: Curve::Linear,
            active: false,
        }
    }

    pub fn start(&mut self, from: i32, to: i32, duration_ms: DurationMs, curve: Curve) {
        self.from = from;
        self.to = to;
        self.value = from;
        self.elapsed_ms = 0;
        self.duration_ms = duration_ms.clamped();
        self.curve = curve;
        self.active = true;
    }

    pub fn step(&mut self, dt_ms: u32) {
        if !self.active {
            return;
        }
        self.elapsed_ms = self.elapsed_ms.saturating_add(dt_ms);
        let p = ((self.elapsed_ms.min(self.duration_ms.0) as u64 * UNIT as u64)
            / self.duration_ms.0 as u64) as u16;
        let e = apply(self.curve, p) as i64;
        let d = (self.to as i64) - (self.from as i64);
        self.value = self.from + ((d * e) / UNIT as i64) as i32;
        if self.elapsed_ms >= self.duration_ms.0 {
            self.value = self.to;
            self.active = false;
        }
    }
}
