fn gf_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11D;
        }
        i += 1;
    }
    let mut j = 255usize;
    while j < 512 {
        exp[j] = exp[j - 255];
        j += 1;
    }
    (exp, log)
}

fn gmul(a: u8, b: u8, exp: &[u8; 512], log: &[u8; 256]) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        exp[log[a as usize] as usize + log[b as usize] as usize]
    }
}

pub fn rs_ecc(data: &[u8], out: &mut [u8]) -> usize {
    let ec = out.len();
    if ec == 0 || ec >= 255 {
        return 0;
    }
    let (exp, log) = gf_tables();
    let mut gen = [0u8; 256];
    gen[0] = 1;
    let mut glen = 1usize;
    for i in 0..ec {
        let mut ng = [0u8; 256];
        for k in 0..glen {
            ng[k] ^= gmul(gen[k], exp[i], &exp, &log);
            ng[k + 1] ^= gen[k];
        }
        glen += 1;
        gen[..glen].copy_from_slice(&ng[..glen]);
    }
    let n = data.len();
    let mut buf = [0u8; 512];
    if n + ec > buf.len() {
        return 0;
    }
    buf[..n].copy_from_slice(data);
    for i in 0..n {
        let coef = buf[i];
        if coef != 0 {
            for k in 1..glen {
                buf[i + k] ^= gmul(gen[k], coef, &exp, &log);
            }
        }
    }
    let take = ec.min(out.len());
    out[..take].copy_from_slice(&buf[n..n + take]);
    take
}

pub fn parity_ecc(data: &[u8], out: &mut [u8]) -> usize {
    rs_ecc(data, out)
}
