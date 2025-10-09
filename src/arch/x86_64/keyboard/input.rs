//! Kernel Input Event Multiplexer

use alloc::collections::VecDeque;
use spin::Mutex;

#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    KeyPress(u8),
    KeyRelease(u8),
    MouseMove { dx: i32, dy: i32 },
    MouseButton { button: u8, pressed: bool },
    UsbRaw { report: [u8; 8] },
    // Extend for more devices
}

static INPUT_QUEUE: Mutex<VecDeque<InputEvent>> = Mutex::new(VecDeque::new());

/// Push event into the queue (from driver ISR)
pub fn push_event(event: InputEvent) {
    INPUT_QUEUE.lock().push_back(event);
}

/// Pop event (non-blocking)
pub fn pop_event() -> Option<InputEvent> {
    INPUT_QUEUE.lock().pop_front()
}

/// Get all pending events (drain)
pub fn drain_events() -> Vec<InputEvent> {
    INPUT_QUEUE.lock().drain(..).collect()
}
