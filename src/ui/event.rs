//! Event system for UI

pub enum Event {
    KeyPress(u8),
    KeyRelease(u8),
    MouseMove(i16, i16),
    MouseClick(u8),
    ProofRoot { root: [u8; 32], epoch: u64 },
    Heartbeat { ms: u64, rq: [usize; 5] },
}

pub enum Pri {
    Low,
    Norm,
    Normal,
    High,
    Critical,
}

pub fn publish(_event: Event, _priority: Pri) {
    // Event publishing stub
}

pub fn publish_pri(event: Event, priority: Pri) {
    publish(event, priority);
}
