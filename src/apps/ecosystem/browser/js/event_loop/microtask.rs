extern crate alloc;
use alloc::collections::VecDeque;
use super::super::runtime::JsValue;

pub struct MicrotaskQueue {
    tasks: VecDeque<Microtask>,
}

pub struct Microtask {
    pub callback: JsValue,
}

impl MicrotaskQueue {
    pub fn new() -> Self {
        Self { tasks: VecDeque::new() }
    }

    pub fn enqueue(&mut self, callback: JsValue) {
        self.tasks.push_back(Microtask { callback });
    }

    pub fn drain(&mut self) -> alloc::vec::Vec<JsValue> {
        let mut callbacks = alloc::vec::Vec::new();
        while let Some(task) = self.tasks.pop_front() {
            callbacks.push(task.callback);
        }
        callbacks
    }

    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }
}
