#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurationMs(pub u32);

impl DurationMs {
	pub const fn clamped(self) -> Self {
		if self.0 == 0 {
			Self(1)
		} else {
			self
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameClock {
	pub now_ms: u64,
}

impl FrameClock {
	pub const fn new(now_ms: u64) -> Self {
		Self { now_ms }
	}

	pub fn tick(&mut self, dt_ms: u32) {
		self.now_ms = self.now_ms.saturating_add(dt_ms as u64);
	}
}
