//! NØNOS Kernel RunQueue 
use alloc::collections::VecDeque;
use crate::sched::task::Task;

pub struct RunQueue {
    queue: VecDeque<Task>,
}

impl RunQueue {
    pub fn new() -> Self {
        Self { queue: VecDeque::new() }
    }

    /// Add a task to the queue
    pub fn push(&mut self, task: Task) {
        self.queue.push_back(task);
    }

    /// Remove and return the next task (FIFO)
    pub fn pop(&mut self) -> Option<Task> {
        self.queue.pop_front()
    }

    /// Get the number of tasks in the queue
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Clear the queue
    pub fn clear(&mut self) {
        self.queue.clear();
    }

    /// Is the queue empty?
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
