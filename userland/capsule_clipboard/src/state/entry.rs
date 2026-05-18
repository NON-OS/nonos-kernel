use alloc::vec::Vec;

pub struct Entry {
    pub content_type: u32,
    pub data: Vec<u8>,
}

impl Entry {
    pub fn len(&self) -> usize {
        self.data.len()
    }
}
