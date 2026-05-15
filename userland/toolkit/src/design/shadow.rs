use crate::design::color::Argb;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Shadow {
	pub x: i16,
	pub y: i16,
	pub blur: u16,
	pub spread: i16,
	pub color: Argb,
}

impl Shadow {
	pub const fn none() -> Self {
		Self { x: 0, y: 0, blur: 0, spread: 0, color: Argb::TRANSPARENT }
	}

	pub const fn sm() -> Self {
		Self { x: 0, y: 1, blur: 3, spread: 0, color: Argb::from_channels(0x38, 0x00, 0x00, 0x00) }
	}

	pub const fn md() -> Self {
		Self { x: 0, y: 3, blur: 8, spread: -1, color: Argb::from_channels(0x40, 0x00, 0x00, 0x00) }
	}
}
