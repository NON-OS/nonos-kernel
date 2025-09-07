//! Event system for UI

pub enum Event {
    KeyPress(u8),
    MouseMove(i32, i32),
    Other(u32),
}

pub enum Pri {
    Low,
    Medium, 
    High,
    Normal,
}

pub fn publish(_event: Event, _priority: Pri) {
    // Stub implementation
}
