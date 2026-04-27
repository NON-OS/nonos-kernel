extern crate alloc;
use super::super::runtime::JsValue;
use super::microtask::MicrotaskQueue;
use super::timers::TimerStore;
use alloc::vec::Vec;

pub struct TickResult {
    pub microtasks_fired: Vec<JsValue>,
    pub timer_fired: Option<JsValue>,
}

pub fn event_loop_tick(
    microtasks: &mut MicrotaskQueue,
    timers: &mut TimerStore,
    now: u64,
) -> TickResult {
    let microtask_callbacks = microtasks.drain();

    let mut timer_callback = None;
    let expired = timers.fire_expired(now);
    if let Some(cb) = expired.into_iter().next() {
        timer_callback = Some(cb);
    }

    TickResult { microtasks_fired: microtask_callbacks, timer_fired: timer_callback }
}
