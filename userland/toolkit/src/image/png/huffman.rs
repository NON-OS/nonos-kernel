use crate::image::png::deflate::BitReader;
use crate::image::types::DecodeError;

pub const MAX_SYMBOLS: usize = 288;

pub struct Huffman {
    counts: [u16; 16],
    symbols: [u16; MAX_SYMBOLS],
}

impl Huffman {
    pub fn from_lengths(lengths: &[u8]) -> Result<Self, DecodeError> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if l as usize > 15 {
                return Err(DecodeError::Unsupported);
            }
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        let mut offsets = [0u16; 16];
        let mut i = 1usize;
        while i < 15 {
            offsets[i + 1] = offsets[i] + counts[i];
            i += 1;
        }
        let mut symbols = [0u16; MAX_SYMBOLS];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let o = offsets[l as usize] as usize;
                if o >= MAX_SYMBOLS {
                    return Err(DecodeError::Unsupported);
                }
                symbols[o] = sym as u16;
                offsets[l as usize] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    pub fn decode(&self, bits: &mut BitReader<'_>) -> Result<u16, DecodeError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        let mut len = 1usize;
        while len < 16 {
            code |= bits.read_bits(1)? as i32;
            let count = self.counts[len] as i32;
            if code - first < count {
                let pos = (index + (code - first)) as usize;
                return self.symbols.get(pos).copied().ok_or(DecodeError::Unsupported);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
            len += 1;
        }
        Err(DecodeError::Unsupported)
    }
}
