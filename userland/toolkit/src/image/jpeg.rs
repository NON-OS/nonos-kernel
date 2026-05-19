use crate::image::types::{DecodeError, ImageSize};

fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(o)?, *b.get(o + 1)?]))
}

pub fn parse_jpeg_header(input: &[u8]) -> Result<(ImageSize, u8), DecodeError> {
    if input.get(0..2) != Some(&[0xFF, 0xD8]) {
        return Err(DecodeError::BadMagic);
    }
    let mut o = 2usize;
    loop {
        if input.get(o) != Some(&0xFF) {
            return Err(DecodeError::Truncated);
        }
        let marker = *input.get(o + 1).ok_or(DecodeError::Truncated)?;
        o += 2;
        match marker {
            0xD9 => return Err(DecodeError::Unsupported),
            0x01 | 0xD0..=0xD7 => continue,
            0xC0 => {
                let h = be16(input, o + 3).ok_or(DecodeError::Truncated)?;
                let w = be16(input, o + 5).ok_or(DecodeError::Truncated)?;
                let comps = *input.get(o + 7).ok_or(DecodeError::Truncated)?;
                return Ok((ImageSize::new(w as u32, h as u32)?, comps));
            }
            0xC1..=0xCF if marker != 0xC4 && marker != 0xC8 => {
                return Err(DecodeError::Unsupported);
            }
            _ => {
                let seg = be16(input, o).ok_or(DecodeError::Truncated)? as usize;
                if seg < 2 {
                    return Err(DecodeError::Truncated);
                }
                o += seg;
            }
        }
    }
}

pub fn decode_jpeg_argb8888(input: &[u8], out: &mut [u32]) -> Result<ImageSize, DecodeError> {
    let (size, comps) = parse_jpeg_header(input)?;
    if comps != 1 && comps != 3 {
        return Err(DecodeError::Unsupported);
    }
    if (size.pixel_count() as usize) > out.len() {
        return Err(DecodeError::OutputTooSmall);
    }
    Err(DecodeError::Unsupported)
}
