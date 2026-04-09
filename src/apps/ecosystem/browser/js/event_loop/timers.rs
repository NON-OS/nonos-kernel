extern crate alloc;
use alloc::vec::Vec;
use super::super::runtime::JsValue;

pub type TimerId = u32;

struct Timer {
    id: TimerId,
    callback: JsValue,
    delay_ms: u64,
    scheduled_at: u64,
    repeating: bool,
    cancelled: bool,
}

pub struct TimerStore {
    timers: Vec<Timer>,
    next_id: TimerId,
}

impl TimerStore {
    pub fn new() -> Self {
        Self { timers: Vec::new(), next_id: 1 }
    }

    pub fn set_timeout(&mut self, callback: JsValue, delay_ms: u64, now: u64) -> TimerId {
        let id = self.next_id;
        self.next_id += 1;
        self.timers.push(Timer { id, callback, delay_ms, scheduled_at: now, repeating: false, cancelled: false });
        id
    }

    pub fn set_interval(&mut self, callback: JsValue, delay_ms: u64, now: u64) -> TimerId {
        let id = self.next_id;
        self.next_id += 1;
        self.timers.push(Timer { id, callback, delay_ms, scheduled_at: now, repeating: true, cancelled: false });
        id
    }

    pub fn clear(&mut self, id: TimerId) {
        for timer in &mut self.timers {
            if timer.id == id { timer.cancelled = true; }
        }
    }

    pub fn fire_expired(&mut self, now: u64) -> Vec<JsValue> {
        let mut callbacks = Vec::new();
        for timer in &mut self.timers {
            if timer.cancelled { continue; }
            if now >= timer.scheduled_at + timer.delay_ms {
                callbacks.push(timer.callback.clone());
                if timer.repeating {
                    timer.scheduled_at = now;
                } else {
                    timer.cancelled = true;
                }
            }
        }
        self.timers.retain(|t| !t.cancelled || t.repeating);
        callbacks
    }
}
