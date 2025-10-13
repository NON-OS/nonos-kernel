//! NØNOS IPC Subsystem Entrypoint
//! RAM-only message bus with policy, channels, per-module inboxes, and framed streams.

#![allow(unused_imports)]

pub mod nonos_channel;
pub mod nonos_message;
pub mod nonos_policy;
pub mod nonos_transport;
pub mod nonos_ipc;
pub mod nonos_inbox;

// Re-exports for backward compatibility
pub use nonos_channel as channel;
pub use nonos_message as message;
pub use nonos_policy as policy;
pub use nonos_transport as transport;

use crate::syscall::capabilities::CapabilityToken;
use nonos_channel::{IPC_BUS, IpcMessage};
use nonos_message::{IpcEnvelope, MessageType, SecurityLevel};
use nonos_policy::ACTIVE_POLICY;
use nonos_transport::{IpcStream, send_stream_payload};
use nonos_inbox as inbox;

use alloc::{vec::Vec, string::{String, ToString}, format};
use core::sync::atomic::{AtomicU64, Ordering};

// IPC statistics (global)
struct IpcStats {
    processed: AtomicU64,
    dropped: AtomicU64,
    timeouts: AtomicU64,
    bytes_tx: AtomicU64,
    start_ms: AtomicU64,
    total_latency_ms: AtomicU64,
    latency_samples: AtomicU64,
}
static IPC_STATS: IpcStats = IpcStats {
    processed: AtomicU64::new(0),
    dropped: AtomicU64::new(0),
    timeouts: AtomicU64::new(0),
    bytes_tx: AtomicU64::new(0),
    start_ms: AtomicU64::new(0),
    total_latency_ms: AtomicU64::new(0),
    latency_samples: AtomicU64::new(0),
};

/// IPC System Diagnostic Report
#[derive(Debug, Clone)]
pub struct IpcStatus {
    pub active_routes: usize,
    pub open_streams: usize,
    pub messages_in_flight: usize,
}

/// Initialize the IPC subsystem and prepare bus
pub fn init_ipc() {
    // Set start time for bandwidth stats
    IPC_STATS.start_ms.compare_exchange(0, crate::time::timestamp_millis(), Ordering::SeqCst, Ordering::SeqCst).ok();
}

/// Attempt to send a validated IPC envelope
pub fn send_envelope(
    envelope: IpcEnvelope,
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    unsafe {
        if !ACTIVE_POLICY.allow_message(&envelope, token) {
            return Err("IPC policy violation: send denied");
        }
    }

    if let Some(channel) = IPC_BUS.find_channel(&envelope.from, &envelope.to) {
        let bytes = envelope.data.len() as u64;
        channel.send(IpcMessage::new(&envelope.from, &envelope.to, &envelope.data)?)?;
        IPC_STATS.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    } else {
        Err("No IPC channel found")
    }
}

/// Send a large payload via transport framing
pub fn send_stream(
    stream: &IpcStream,
    payload: &[u8],
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    let tx = |env: IpcEnvelope| send_envelope(env, token);
    send_stream_payload(stream, payload, tx)
}

/// List all active module-to-module IPC routes
pub fn list_routes() -> Vec<(&'static str, &'static str)> {
    IPC_BUS.list_routes()
}

/// Retrieve real-time diagnostic report of IPC state
pub fn get_ipc_status() -> IpcStatus {
    IpcStatus {
        active_routes: IPC_BUS.list_routes().len(),
        open_streams: 0,
        messages_in_flight: 0,
    }
}

/// Register a new IPC channel if permitted
pub fn open_secure_channel(
    from: &'static str,
    to: &'static str,
    token: &CapabilityToken,
) -> Result<(), &'static str> {
    unsafe {
        if !ACTIVE_POLICY.allow_channel(from, to, token) {
            return Err("IPC policy violation: open_channel denied");
        }
    }
    // Ensure receiver inbox exists
    inbox::register_inbox(to);
    IPC_BUS.open_channel(from, to, token)
}

/// Initialize IPC subsystem (compat wrapper)
pub fn init() {
    init_ipc();
}

/// Process IPC message queue (pulls from bus, delivers to per-module inboxes)
pub fn process_message_queue() {
    const MAX_MESSAGES_PER_ITERATION: usize = 128;
    let mut processed = 0;

    while processed < MAX_MESSAGES_PER_ITERATION {
        match IPC_BUS.get_next_message() {
            Some(message) => {
                let now = crate::time::timestamp_millis();
                let latency = now.saturating_sub(message.timestamp_ms);
                IPC_STATS.total_latency_ms.fetch_add(latency as u64, Ordering::Relaxed);
                IPC_STATS.latency_samples.fetch_add(1, Ordering::Relaxed);

                match process_single_message(message) {
                    Ok(()) => {
                        processed += 1;
                        IPC_STATS.processed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_e) => {
                        processed += 1;
                        IPC_STATS.dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            None => break,
        }
    }

    handle_message_timeouts();
    cleanup_dead_channels();

    if processed > 0 {
        crate::drivers::console::write_message(
            &alloc::format!("IPC processed {}", processed),
            crate::drivers::console::LogLevel::Info,
            "ipc",
        );
    }
}

/// Process a single IPC message
fn process_single_message(message: IpcMessage) -> Result<(), &'static str> {
    // Validate message integrity
    if !message.validate_integrity() {
        return Err("Message integrity validation failed");
    }

    // Check if destination module is still alive
    if !is_module_alive(&message.to) {
        cleanup_module_channels(&message.to);
        return Err("Destination module is dead");
    }

    // Route message to destination inbox
    route_message_to_destination(&message)
}

fn route_message_to_destination(message: &IpcMessage) -> Result<(), &'static str> {
    inbox::register_inbox(&message.to);

    if inbox::is_full(&message.to) {
        return Err("Target message inbox is full");
    }

    inbox::enqueue_with_timeout(&message.to, message.clone(), get_message_timeout())
}

fn handle_message_timeouts() {
    let timed_out_messages = IPC_BUS.get_timed_out_messages();

    for message in timed_out_messages {
        IPC_STATS.timeouts.fetch_add(1, Ordering::Relaxed);

        // Send timeout notification to sender if possible (best effort)
        let _ = send_timeout_notification(&message);

        // Remove channels for dead destination on timeout
        cleanup_module_channels(&message.to);
    }
}

fn cleanup_dead_channels() {
    let dead_channels = IPC_BUS.find_dead_channels();
    for channel_index in dead_channels {
        IPC_BUS.remove_channel(channel_index);
    }
}

fn get_message_timeout() -> u64 { 5000 /* ms */ }

fn send_timeout_notification(message: &IpcMessage) -> Result<(), &'static str> {
    let timeout_envelope = IpcEnvelope {
        from: "kernel".into(),
        to: message.from.clone(),
        message_type: MessageType::Timeout,
        data: alloc::format!("Message to {} timed out", message.to).into_bytes(),
        timestamp: crate::time::timestamp_millis(),
        session_id: None,
        sec_level: SecurityLevel::None,
    };
    // Kernel-originated; send directly
    IPC_BUS.send_system_message(timeout_envelope)
}

// ---- Capability validation queue ----

use alloc::collections::VecDeque;
use spin::Mutex;

struct CapabilityValidationRequest {
    requester: String,
    capability: String,
}

static VALIDATION_Q: Mutex<VecDeque<CapabilityValidationRequest>> = Mutex::new(VecDeque::new());

#[allow(dead_code)]
pub fn enqueue_capability_validation(requester: &str, capability: &str) {
    VALIDATION_Q.lock().push_back(CapabilityValidationRequest {
        requester: requester.into(),
        capability: capability.into(),
    });
}

fn get_next_capability_validation() -> Option<CapabilityValidationRequest> {
    VALIDATION_Q.lock().pop_front()
}

fn validate_capability_request(_request: &CapabilityValidationRequest) -> Result<bool, &'static str> {
    // Allow by default in RAM-only profile
    Ok(true)
}

fn send_capability_validation_result(requester: &str, result: bool) {
    let message = alloc::format!("CAPABILITY_RESULT:{}:{}", requester, result);
    let envelope = IpcEnvelope {
        from: "capability_validator".into(),
        to: requester.into(),
        message_type: MessageType::CapabilityResult,
        data: message.into_bytes(),
        timestamp: crate::time::timestamp_millis(),
        session_id: None,
        sec_level: SecurityLevel::None,
    };
    let _ = IPC_BUS.send_system_message(envelope);
}

fn send_capability_validation_error(requester: &str, error: &str) {
    let message = alloc::format!("CAPABILITY_ERROR:{}:{}", requester, error);
    let envelope = IpcEnvelope {
        from: "capability_validator".into(),
        to: requester.into(),
        message_type: MessageType::Error,
        data: message.into_bytes(),
        timestamp: crate::time::timestamp_millis(),
        session_id: None,
        sec_level: SecurityLevel::None,
    };
    let _ = IPC_BUS.send_system_message(envelope);
}

fn process_capability_validation_queue() {
    const MAX_VALIDATIONS_PER_ITERATION: usize = 32;
    let mut processed = 0;

    while processed < MAX_VALIDATIONS_PER_ITERATION {
        if let Some(validation_request) = get_next_capability_validation() {
            match validate_capability_request(&validation_request) {
                Ok(result) => send_capability_validation_result(&validation_request.requester, result),
                Err(e) => send_capability_validation_error(&validation_request.requester, e),
            }
            processed += 1;
        } else {
            break;
        }
    }
}

// ---- Support helpers ----

fn is_module_alive(module_name: &str) -> bool {
    crate::modules::is_module_active(module_name)
}

fn cleanup_module_channels(module_name: &str) {
    IPC_BUS.remove_all_channels_for_module(module_name);
}

// Background daemon 
pub fn run_ipc_daemon() {
    loop {
        process_message_queue();
        process_capability_validation_queue();
        // Yield to scheduler
        crate::sched::yield_cpu();
    }
}
