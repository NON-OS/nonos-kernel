//! ChaCha20-based CSPRNG 

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::ptr;
use spin::Mutex;

static GLOBAL_INIT: AtomicBool = AtomicBool::new(false);
static GLOBAL_COUNTER: AtomicU64 = AtomicU64::new(1);
static mut GLOBAL_RNG: Option<Mutex<ChaChaRng>> = None;

/// ChaCha20 core-based RNG
pub struct ChaChaRng {
    key: [u8; 32],
    state: [u32; 16],
    output: [u8; 64],
    index: usize,
}

impl ChaChaRng {
    pub fn new(seed: [u8; 32]) -> Self {
        let mut s = Self {
            key: seed,
            state: [0u32; 16],
            output: [0u8; 64],
            index: 64,
        };
        s.rekey(seed);
        s
    }

    fn rekey(&mut self, seed: [u8; 32]) {
        self.key = seed;
        // ChaCha20 constants
        self.state[0] = 0x6170_7865;
        self.state[1] = 0x3320_646e;
        self.state[2] = 0x7962_2d32;
        self.state[3] = 0x6b20_6574;
        // 256-bit key, little-endian words
        for i in 0..8 {
            let j = i * 4;
            self.state[4 + i] =
                u32::from_le_bytes([seed[j], seed[j + 1], seed[j + 2], seed[j + 3]]);
        }
        // counter and nonce zero (counter increments as it generate)
        self.state[12] = 0;
        self.state[13] = 0;
        self.state[14] = 0;
        self.state[15] = 0;
        self.index = 64; // force regenerate on next use
    }

    #[inline(always)]
    fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);

        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);

        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);

        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }

    fn generate_block(&mut self) {
        let mut working = self.state;
        // 20 rounds (10 double rounds)
        for _ in 0..10 {
            // column rounds
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            // diagonal rounds
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
        }
        // add original state
        for i in 0..16 {
            working[i] = working[i].wrapping_add(self.state[i]);
        }
        // serialize keystream (little endian)
        for (i, w) in working.iter().enumerate() {
            let bytes = w.to_le_bytes();
            let off = i * 4;
            self.output[off..off + 4].copy_from_slice(&bytes);
        }
        // increment 64-bit counter (state[12], state[13])
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        self.index = 0;
    }

    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            if self.index >= 64 {
                self.generate_block();
            }
            let take = core::cmp::min(64 - self.index, out.len() - written);
            out[written..written + take]
                .copy_from_slice(&self.output[self.index..self.index + take]);
            self.index += take;
            written += take;
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut tmp = [0u8; 8];
        self.fill_bytes(&mut tmp);
        u64::from_le_bytes(tmp)
    }

    pub fn reseed(&mut self, seed: [u8; 32]) {
        self.rekey(seed);
        for b in &mut self.output {
            unsafe { ptr::write_volatile(b, 0) };
        }
        self.index = 64;
    }
}

impl Drop for ChaChaRng {
    fn drop(&mut self) {
        for b in &mut self.key {
            unsafe { ptr::write_volatile(b, 0) };
        }
        for w in &mut self.state {
            unsafe { ptr::write_volatile(w, 0) };
        }
        for b in &mut self.output {
            unsafe { ptr::write_volatile(b, 0) };
        }
        self.index = 0;
    }
}

/// Best-effort entropy collection
fn get_entropy64() -> u64 {
    let mut e = GLOBAL_COUNTER.fetch_add(1, Ordering::SeqCst);
    // RDTSC on x86_64 if available
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut lo: u32 = 0;
        let mut hi: u32 = 0;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
        e ^= (lo as u64) | ((hi as u64) << 32);
    }
    // pointer jitter
    let addr = &e as *const u64 as u64;
    e ^= addr;
    e
}

/// Initialize global RNG (idempotent)
pub fn init_rng() {
    if GLOBAL_INIT.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut seed = [0u8; 32];
    for i in 0..4 {
        let v = get_entropy64();
        seed[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    unsafe {
        GLOBAL_RNG = Some(Mutex::new(ChaChaRng::new(seed)));
    }
}

/// Reseed or seed the global RNG (best-effort)
pub fn seed_rng() {
    let mut seed = [0u8; 32];
    for i in 0..4 {
        let v = get_entropy64();
        seed[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    unsafe {
        if let Some(r) = &GLOBAL_RNG {
            r.lock().reseed(seed);
        } else {
            GLOBAL_RNG = Some(Mutex::new(ChaChaRng::new(seed)));
            GLOBAL_INIT.store(true, Ordering::Release);
        }
    }
}

/// Get 32 random bytes from global RNG. Ensures RNG initialized.
pub fn get_random_bytes() -> [u8; 32] {
    if !GLOBAL_INIT.load(Ordering::Acquire) {
        init_rng();
    }
    let mut out = [0u8; 32];
    unsafe {
        if let Some(r) = &GLOBAL_RNG {
            r.lock().fill_bytes(&mut out);
        } else {
            // fallback (unlikely)
            let v = get_entropy64();
            out[..8].copy_from_slice(&v.to_le_bytes());
        }
    }
    out
}

/// Fill a buffer with random bytes.
pub fn fill_random_bytes(buf: &mut [u8]) {
    if !GLOBAL_INIT.load(Ordering::Acquire) {
        init_rng();
    }
    unsafe {
        if let Some(r) = &GLOBAL_RNG {
            r.lock().fill_bytes(buf);
        } else {
            for chunk in buf.chunks_mut(8) {
                let v = get_entropy64();
                let bytes = v.to_le_bytes();
                for (i, b) in chunk.iter_mut().enumerate() {
                    *b = bytes[i];
                }
            }
        }
    }
}

/// Random u64
pub fn random_u64() -> u64 {
    if !GLOBAL_INIT.load(Ordering::Acquire) {
        init_rng();
    }
    unsafe {
        if let Some(r) = &GLOBAL_RNG {
            return r.lock().next_u64();
        }
    }
    get_entropy64()
}

/// Random u32
pub fn random_u32() -> u32 {
    (random_u64() & 0xFFFF_FFFF) as u32
}
