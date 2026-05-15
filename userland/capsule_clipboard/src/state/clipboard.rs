use alloc::collections::VecDeque;

use super::Entry;

pub struct Clipboard {
    items: VecDeque<Entry>,
    total_bytes: usize,
    max_depth: usize,
    max_total_bytes: usize,
}

impl Clipboard {
    pub fn new(max_depth: usize, max_total_bytes: usize) -> Self {
        Self { items: VecDeque::new(), total_bytes: 0, max_depth, max_total_bytes }
    }

    pub fn copy(&mut self, content_type: u32, data: &[u8]) {
        self.items.push_front(Entry { content_type, data: data.to_vec() });
        self.total_bytes += data.len();
        while self.items.len() > self.max_depth || self.total_bytes > self.max_total_bytes {
            if let Some(tail) = self.items.pop_back() {
                self.total_bytes = self.total_bytes.saturating_sub(tail.len());
            } else {
                break;
            }
        }
    }

    pub fn latest_of_type(&self, content_type: u32) -> Option<&Entry> {
        self.items.iter().find(|e| e.content_type == content_type)
    }

    pub fn get_by_index(&self, index: usize) -> Option<&Entry> {
        self.items.get(index)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.items.iter()
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.total_bytes = 0;
    }
}
