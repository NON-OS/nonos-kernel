#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argb(pub u32);

impl Argb {
	pub const BLACK: Self = Self(0xFF00_0000);
	pub const WHITE: Self = Self(0xFFFF_FFFF);
	pub const TRANSPARENT: Self = Self(0x0000_0000);

	pub const fn from_channels(a: u8, r: u8, g: u8, b: u8) -> Self {
		Self(((a as u32) << 24) | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32))
	}

	pub const fn with_alpha(self, a: u8) -> Self {
		Self((self.0 & 0x00FF_FFFF) | ((a as u32) << 24))
	}

	pub const fn alpha(self) -> u8 {
		((self.0 >> 24) & 0xFF) as u8
	}

	pub const fn as_u32(self) -> u32 {
		self.0
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Palette {
	pub background: Argb,
	pub foreground: Argb,
	pub accent: Argb,
	pub danger: Argb,
}

impl Default for Palette {
	fn default() -> Self {
		Self {
			background: Argb::from_channels(0xFF, 0x0C, 0x0E, 0x13),
			foreground: Argb::from_channels(0xFF, 0xEE, 0xF1, 0xF6),
			accent: Argb::from_channels(0xFF, 0x2A, 0x7D, 0xD6),
			danger: Argb::from_channels(0xFF, 0xC8, 0x3A, 0x2B),
		}
	}
}
