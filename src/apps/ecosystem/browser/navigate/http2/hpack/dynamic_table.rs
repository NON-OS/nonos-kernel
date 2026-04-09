extern crate alloc;
use alloc::string::String;
use alloc::collections::VecDeque;

pub struct DynamicTable {
    entries: VecDeque<(String, String)>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        Self { entries: VecDeque::new(), size: 0, max_size }
    }

    pub fn insert(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32;
        self.evict(entry_size);
        if entry_size <= self.max_size {
            self.size += entry_size;
            self.entries.push_front((name, value));
        }
    }

    pub fn get(&self, index: usize) -> Option<(&str, &str)> {
        self.entries.get(index).map(|(n, v)| (n.as_str(), v.as_str()))
    }

    pub fn len(&self) -> usize { self.entries.len() }

    pub fn set_max_size(&mut self, max: usize) {
        self.max_size = max;
        self.evict(0);
    }

    fn evict(&mut self, needed: usize) {
        while self.size + needed > self.max_size {
            if let Some((name, value)) = self.entries.pop_back() {
                self.size -= name.len() + value.len() + 32;
            } else { break; }
        }
    }

    pub fn find(&self, name: &str, value: &str) -> Option<usize> {
        for (i, (n, v)) in self.entries.iter().enumerate() {
            if n == name && v == value { return Some(i); }
        }
        None
    }

    pub fn find_name(&self, name: &str) -> Option<usize> {
        for (i, (n, _)) in self.entries.iter().enumerate() {
            if n == name { return Some(i); }
        }
        None
    }
}
