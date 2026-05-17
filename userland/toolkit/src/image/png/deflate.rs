use crate::image::types::DecodeError;

#[derive(Clone, Copy)]
pub struct BitReader<'a> {
	src: &'a [u8],
	byte: usize,
	bit: u8,
}

impl<'a> BitReader<'a> {
	pub const fn new(src: &'a [u8]) -> Self {
		Self { src, byte: 0, bit: 0 }
	}

	pub fn read_bits(&mut self, count: u8) -> Result<u16, DecodeError> {
		let mut out = 0u16;
		let mut i = 0u8;
		while i < count {
			let b = *self.src.get(self.byte).ok_or(DecodeError::Truncated)?;
			let v = (b >> self.bit) & 1;
			out |= (v as u16) << i;
			self.bit += 1;
			if self.bit == 8 {
				self.bit = 0;
				self.byte += 1;
			}
			i += 1;
		}
		Ok(out)
	}

	pub fn align_byte(&mut self) {
		if self.bit != 0 {
			self.bit = 0;
			self.byte += 1;
		}
	}

	pub fn offset(self) -> usize {
		self.byte
	}
}
