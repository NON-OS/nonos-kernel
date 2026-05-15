use crate::image::png::deflate::BitReader;
use crate::image::types::DecodeError;

pub fn inflate_zlib_stored_only(src: &[u8], out: &mut [u8]) -> Result<usize, DecodeError> {
	if src.len() < 2 {
		return Err(DecodeError::Truncated);
	}
	let mut bits = BitReader::new(&src[2..]);
	let mut written = 0usize;
	loop {
		let final_block = bits.read_bits(1)? as u8;
		let btype = bits.read_bits(2)? as u8;
		if btype != 0 {
			return Err(DecodeError::Unsupported);
		}
		bits.align_byte();
		let off = bits.offset();
		let body = &src[2 + off..];
		if body.len() < 4 {
			return Err(DecodeError::Truncated);
		}
		let len = u16::from_le_bytes([body[0], body[1]]);
		let nlen = u16::from_le_bytes([body[2], body[3]]);
		if len != !nlen {
			return Err(DecodeError::BadMagic);
		}
		let n = len as usize;
		let data = body.get(4..4 + n).ok_or(DecodeError::Truncated)?;
		if written + n > out.len() {
			return Err(DecodeError::OutputTooSmall);
		}
		out[written..written + n].copy_from_slice(data);
		written += n;
		let new_off = off + 4 + n;
		bits = BitReader::new(&src[2 + new_off..]);
		if final_block != 0 {
			return Ok(written);
		}
	}
}
