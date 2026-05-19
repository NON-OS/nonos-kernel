use crate::image::types::DecodeError;

const BPP: usize = 4;

fn paeth(a: i32, b: i32, c: i32) -> i32 {
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

pub fn unfilter(raw: &[u8], width: u32, height: u32, out: &mut [u8]) -> Result<usize, DecodeError> {
    let row_bytes = (width as usize).saturating_mul(BPP);
    let h = height as usize;
    let needed = row_bytes.saturating_add(1).saturating_mul(h);
    if raw.len() < needed {
        return Err(DecodeError::Truncated);
    }
    let out_needed = row_bytes.saturating_mul(h);
    if out.len() < out_needed {
        return Err(DecodeError::OutputTooSmall);
    }
    let mut src = 0usize;
    for row in 0..h {
        let filter = raw[src];
        src += 1;
        let base = row * row_bytes;
        for i in 0..row_bytes {
            let x = raw[src + i] as i32;
            let a = if i >= BPP { out[base + i - BPP] as i32 } else { 0 };
            let b = if row > 0 { out[base - row_bytes + i] as i32 } else { 0 };
            let c = if row > 0 && i >= BPP { out[base - row_bytes + i - BPP] as i32 } else { 0 };
            let recon = match filter {
                0 => x,
                1 => x + a,
                2 => x + b,
                3 => x + (a + b) / 2,
                4 => x + paeth(a, b, c),
                _ => return Err(DecodeError::Unsupported),
            };
            out[base + i] = (recon & 0xff) as u8;
        }
        src += row_bytes;
    }
    Ok(out_needed)
}
