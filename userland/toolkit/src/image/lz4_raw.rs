use crate::image::types::{DecodeError, ImageSize};

pub fn decode_lz4_raw_argb8888(
    width: u32,
    height: u32,
    decompressed: &[u8],
    out: &mut [u32],
) -> Result<ImageSize, DecodeError> {
    let size = ImageSize::new(width, height)?;
    let count = size.pixel_count() as usize;
    if count > out.len() {
        return Err(DecodeError::OutputTooSmall);
    }
    let bytes_needed = count.saturating_mul(4);
    if decompressed.len() < bytes_needed {
        return Err(DecodeError::Truncated);
    }
    let mut i = 0usize;
    while i < count {
        let off = i * 4;
        out[i] = u32::from_le_bytes([
            decompressed[off],
            decompressed[off + 1],
            decompressed[off + 2],
            decompressed[off + 3],
        ]);
        i += 1;
    }
    Ok(size)
}
