//! Kernel Input Event Multiplexer

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

/// Describes a discrete input event from any device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    KeyPress(u8),
    KeyRelease(u8),
    MouseMove { dx: i32, dy: i32 },
    MouseButton { button: u8, pressed: bool },
    UsbRaw { report: [u8; 8] },
    // Extend for more devices
}

/// Central input event queue (thread-safe).
static INPUT_QUEUE: Mutex<VecDeque<InputEvent>> = Mutex::new(VecDeque::new());

/// Push event into the queue (from driver ISR).
pub fn push_event(event: InputEvent) {
    INPUT_QUEUE.lock().push_back(event);
}

/// Pop event (non-blocking).
pub fn pop_event() -> Option<InputEvent> {
    INPUT_QUEUE.lock().pop_front()
}

/// Get all pending events (drain).
pub fn drain_events() -> Vec<InputEvent> {
    INPUT_QUEUE.lock().drain(..).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_push_and_pop_event() {
        let event = InputEvent::KeyPress(42);
        push_event(event);
        assert_eq!(pop_event(), Some(event));
        assert_eq!(pop_event(), None);
    }
    #[test]
    fn test_drain_events() {
        push_event(InputEvent::KeyPress(1));
        push_event(InputEvent::KeyRelease(1));
        let events = drain_events();
        assert_eq!(events.len(), 2);
        assert_eq!(pop_event(), None);
    }
}
