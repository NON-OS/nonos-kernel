#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
	BadMagic,
	Unsupported,
	BadDimensions,
	OutputTooSmall,
	Truncated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageSize {
	pub width: u32,
	pub height: u32,
}

impl ImageSize {
	pub const fn new(width: u32, height: u32) -> Result<Self, DecodeError> {
		if width == 0 || height == 0 {
			return Err(DecodeError::BadDimensions);
		}
		Ok(Self { width, height })
	}

	pub const fn pixel_count(self) -> u64 {
		self.width as u64 * self.height as u64
	}
}
