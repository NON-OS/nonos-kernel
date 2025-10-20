//! Event bus and event types for the UI subsystem.

#![cfg(feature = "ui")]

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

/// Maximum listeners to avoid unbounded growth.
pub const MAX_EVENT_LISTENERS: usize = 512;
/// Maximum queued events before enqueue returns an error.
pub const MAX_EVENT_QUEUE_LEN: usize = 4096;

/// UI / system events.
#[derive(Clone, Debug)]
pub enum Event {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Window(WindowEvent),
    ClipboardChanged,
    Custom { tag: alloc::string::String, payload: alloc::string::String },
}

#[derive(Clone, Debug)]
pub struct KeyEvent {
    pub scancode: u8,
    pub pressed: bool,
}

#[derive(Clone, Debug)]
pub struct MouseEvent {
    pub x: i32,
    pub y: i32,
    pub button_left: bool,
    pub button_right: bool,
    pub wheel: i32,
}

#[derive(Clone, Debug)]
pub enum WindowEventKind {
    FocusGained,
    FocusLost,
    CloseRequested,
    Resized { width: u32, height: u32 },
}

#[derive(Clone, Debug)]
pub struct WindowEvent {
    pub window_id: u32,
    pub kind: WindowEventKind,
}

/// Listener callback type (Arc so we can clone cheaply and call without holding locks).
pub type Listener = dyn Fn(&Event) + Send + Sync + 'static;

struct ListenerEntry {
    id: u32,
    callback: Arc<Listener>,
}

/// Synchronous publish/subscribe EventBus.
pub struct EventBus {
    listeners: Vec<ListenerEntry>,
    next_listener_id: AtomicU32,
    queue: VecDeque<Event>,
}

static EVENT_BUS: Mutex<Option<EventBus>> = Mutex::new(None);

impl EventBus {
    pub fn new() -> Self {
        EventBus {
            listeners: Vec::new(),
            next_listener_id: AtomicU32::new(1),
            queue: VecDeque::new(),
        }
    }

    /// Register a listener and return an id. Returns Err if listener cap reached.
    pub fn register_listener(&mut self, cb: Arc<Listener>) -> Result<u32, &'static str> {
        if self.listeners.len() >= MAX_EVENT_LISTENERS {
            return Err("max listeners reached");
        }
        let id = self.next_listener_id.fetch_add(1, Ordering::SeqCst);
        self.listeners.push(ListenerEntry { id, callback: cb });
        Ok(id)
    }

    /// Unregister a listener by id.
    pub fn unregister_listener(&mut self, id: u32) -> bool {
        if let Some(pos) = self.listeners.iter().position(|l| l.id == id) {
            self.listeners.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Snapshot listeners (clone Arcs) and return them for invocation.
    fn snapshot_listeners(&self) -> Vec<Arc<Listener>> {
        let mut out = Vec::with_capacity(self.listeners.len());
        for l in &self.listeners {
            out.push(l.callback.clone());
        }
        out
    }

    /// Enqueue an event for deferred dispatch with bounded queue behavior.
    pub fn enqueue(&mut self, ev: Event) -> Result<(), &'static str> {
        if self.queue.len() >= MAX_EVENT_QUEUE_LEN {
            return Err("event queue full");
        }
        self.queue.push_back(ev);
        Ok(())
    }

    /// Drain queued events and take a snapshot of them for outside invocation.
    fn drain_queue(&mut self) -> Vec<Event> {
        let mut events = Vec::with_capacity(self.queue.len());
        while let Some(ev) = self.queue.pop_front() {
            events.push(ev);
        }
        events
    }
}

/// Initialize the global event bus (idempotent).
pub fn init_event_bus() {
    let mut g = EVENT_BUS.lock();
    if g.is_none() {
        *g = Some(EventBus::new());
        crate::log_info!("ui: event bus initialized");
    }
}

/// Register a listener and return its id.
/// Use alloc::sync::Arc::new(callback) to register.
pub fn register_listener(cb: alloc::sync::Arc<Listener>) -> Result<u32, &'static str> {
    // Lock, add listener, snapshot nothing here.
    let mut g = EVENT_BUS.lock();
    if let Some(ref mut bus) = *g {
        bus.register_listener(cb)
    } else {
        Err("event bus not initialized")
    }
}

/// Unregister a listener.
pub fn unregister_listener(id: u32) -> Result<bool, &'static str> {
    let mut g = EVENT_BUS.lock();
    if let Some(ref mut bus) = *g {
        Ok(bus.unregister_listener(id))
    } else {
        Err("event bus not initialized")
    }
}

/// Publish an event synchronously. Callbacks are invoked outside the bus lock.
pub fn publish_event(ev: Event) -> Result<(), &'static str> {
    // Snapshot callbacks
    let callbacks = {
        let g = EVENT_BUS.lock();
        if let Some(ref bus) = *g {
            bus.snapshot_listeners()
        } else {
            return Err("event bus not initialized");
        }
    };
    for cb in callbacks {
        (cb)(&ev);
    }
    Ok(())
}

/// Enqueue an event (bounded). Returns Err if queue full or not initialized.
pub fn enqueue_event(ev: Event) -> Result<(), &'static str> {
    let mut g = EVENT_BUS.lock();
    if let Some(ref mut bus) = *g {
        bus.enqueue(ev)
    } else {
        Err("event bus not initialized")
    }
}

/// Flush queued events: snapshot queued events and listeners, unlock, then invoke callbacks.
pub fn flush_events() -> Result<(), &'static str> {
    let (events, callbacks) = {
        let mut g = EVENT_BUS.lock();
        if let Some(ref mut bus) = *g {
            let events = bus.drain_queue();
            let cbs = bus.snapshot_listeners();
            (events, cbs)
        } else {
            return Err("event bus not initialized");
        }
    };

    for ev in events {
        for cb in &callbacks {
            (cb)(&ev);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn register_and_publish() {
        init_event_bus();
        let called = core::sync::atomic::AtomicU32::new(0);
        let cb = Arc::new(move |_e: &Event| {
            called.fetch_add(1, Ordering::SeqCst);
        }) as Arc<Listener>;
        let id = register_listener(cb.clone()).unwrap();
        publish_event(Event::Custom { tag: "t".into(), payload: "p".into() }).unwrap();
        assert!(called.load(Ordering::SeqCst) >= 1);
        assert!(unregister_listener(id).unwrap());
    }

    #[test]
    fn register_during_callback_no_deadlock() {
        init_event_bus();
        let reg_done = core::sync::atomic::AtomicU32::new(0);
        // Listener A registers listener B when invoked
        let a_cb = {
            let reg_done = &reg_done;
            Arc::new(move |_ev: &Event| {
                // inside callback, we register a new listener; must not deadlock
                let b = Arc::new(|_e: &Event| {}) as Arc<Listener>;
                let _ = register_listener(b);
                reg_done.fetch_add(1, Ordering::SeqCst);
            }) as Arc<Listener>
        };
        let _ = register_listener(a_cb.clone()).unwrap();
        publish_event(Event::Custom { tag: "x".into(), payload: "y".into() }).unwrap();
        assert!(reg_done.load(Ordering::SeqCst) >= 1);
    }
}
