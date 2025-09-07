//! Kernel Address Space Layout Randomization

pub struct Kaslr {
    pub slide: u64,
}

impl Kaslr {
    pub fn new() -> Self {
        Self { slide: 0 }
    }
}
