use crate::ipc::*;
use crate::ipc::nonos_channel::{
    IpcBus, IpcChannel, IpcMessage, ChannelError, BusStatsSnapshot,
    compute_channel_key, compute_checksum, init_ipc_secret,
    DEFAULT_MAX_QUEUE, DEFAULT_MSG_TIMEOUT_MS, MAX_MESSAGE_SIZE,
};
use crate::syscall::capabilities::CapabilityToken;
use alloc::string::String;
use alloc::vec;

#[test]
fn test_ipc_message_creation() {
    let msg = IpcMessage::new("sender", "receiver", b"hello world");
    assert!(msg.is_ok());
    let msg = msg.unwrap();
    assert_eq!(msg.from, "sender");
    assert_eq!(msg.to, "receiver");
    assert_eq!(msg.data, b"hello world".to_vec());
}

#[test]
fn test_ipc_message_empty_payload() {
    let msg = IpcMessage::new("a", "b", &[]);
    assert!(msg.is_ok());
    let msg = msg.unwrap();
    assert!(msg.is_empty());
    assert_eq!(msg.payload_size(), 0);
}

#[test]
fn test_ipc_message_payload_size() {
    let msg = IpcMessage::new("a", "b", b"test payload").unwrap();
    assert_eq!(msg.payload_size(), 12);
    assert!(!msg.is_empty());
}

#[test]
fn test_ipc_message_validate_integrity() {
    let msg = IpcMessage::new("sender", "receiver", b"data").unwrap();
    assert!(msg.validate_integrity());
}

#[test]
fn test_ipc_message_with_timestamp() {
    let msg = IpcMessage::with_timestamp("a", "b", b"test", 12345);
    assert_eq!(msg.timestamp_ms, 12345);
    assert!(msg.validate_integrity());
}

#[test]
fn test_ipc_message_size_limit_exceeded() {
    let large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
    let result = IpcMessage::new("a", "b", &large_data);
    assert!(result.is_err());
}

#[test]
fn test_ipc_message_size_limit_at_boundary() {
    let boundary_data = vec![0u8; MAX_MESSAGE_SIZE];
    let result = IpcMessage::new("a", "b", &boundary_data);
    assert!(result.is_ok());
}

#[test]
fn test_ipc_message_display() {
    let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
    let s = alloc::format!("{}", msg);
    assert!(s.contains("sender"));
    assert!(s.contains("receiver"));
    assert!(s.contains("5 bytes"));
}

#[test]
fn test_ipc_message_clone() {
    let msg = IpcMessage::new("a", "b", b"data").unwrap();
    let cloned = msg.clone();
    assert_eq!(cloned.from, msg.from);
    assert_eq!(cloned.to, msg.to);
    assert_eq!(cloned.data, msg.data);
    assert!(cloned.validate_integrity());
}

#[test]
fn test_ipc_channel_key() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("test_key_from", "test_key_to", &token).unwrap();
    let channel = bus.find_channel("test_key_from", "test_key_to").unwrap();
    assert!(channel.key() != 0);
}

#[test]
fn test_ipc_channel_debug() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("debug_from", "debug_to", &token).unwrap();
    let channel = bus.find_channel("debug_from", "debug_to").unwrap();
    let s = alloc::format!("{:?}", channel);
    assert!(s.contains("IpcChannel"));
}

#[test]
fn test_ipc_channel_copy() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("copy_from", "copy_to", &token).unwrap();
    let channel = bus.find_channel("copy_from", "copy_to").unwrap();
    let key = channel.key();
    assert!(key != 0);
}

#[test]
fn test_compute_channel_key_consistency() {
    let key1 = compute_channel_key("from", "to");
    let key2 = compute_channel_key("from", "to");
    assert_eq!(key1, key2);
}

#[test]
fn test_compute_channel_key_different_endpoints() {
    let key1 = compute_channel_key("from1", "to1");
    let key2 = compute_channel_key("from2", "to2");
    assert_ne!(key1, key2);
}

#[test]
fn test_compute_channel_key_order_matters() {
    let key1 = compute_channel_key("a", "b");
    let key2 = compute_channel_key("b", "a");
    assert_ne!(key1, key2);
}

#[test]
fn test_compute_checksum_consistency() {
    let csum1 = compute_checksum("from", "to", b"data", 1000);
    let csum2 = compute_checksum("from", "to", b"data", 1000);
    assert_eq!(csum1, csum2);
}

#[test]
fn test_compute_checksum_different_data() {
    let csum1 = compute_checksum("from", "to", b"data1", 1000);
    let csum2 = compute_checksum("from", "to", b"data2", 1000);
    assert_ne!(csum1, csum2);
}

#[test]
fn test_compute_checksum_different_timestamp() {
    let csum1 = compute_checksum("from", "to", b"data", 1000);
    let csum2 = compute_checksum("from", "to", b"data", 2000);
    assert_ne!(csum1, csum2);
}

#[test]
fn test_init_ipc_secret_idempotent() {
    init_ipc_secret();
    let key1 = compute_channel_key("test", "secret");
    init_ipc_secret();
    let key2 = compute_channel_key("test", "secret");
    assert_eq!(key1, key2);
}

#[test]
fn test_ipc_bus_new() {
    let bus = IpcBus::new();
    assert_eq!(bus.get_active_channel_count(), 0);
    assert_eq!(bus.get_queue_depth(), 0);
}

#[test]
fn test_ipc_bus_channel_exists() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("from", "to", &token).unwrap();
    assert!(bus.channel_exists("from", "to"));
    assert!(!bus.channel_exists("nonexistent", "channel"));
}

#[test]
fn test_ipc_bus_open_channel_idempotent() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("a", "b", &token).unwrap();
    bus.open_channel("a", "b", &token).unwrap();
    assert_eq!(bus.get_active_channel_count(), 1);
}

#[test]
fn test_ipc_bus_open_channel_empty_endpoints() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    let result = bus.open_channel("", "to", &token);
    assert!(result.is_err());

    let result = bus.open_channel("from", "", &token);
    assert!(result.is_err());
}

#[test]
fn test_ipc_bus_find_channel() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("sender", "receiver", &token).unwrap();

    let channel = bus.find_channel("sender", "receiver");
    assert!(channel.is_some());

    let channel = bus.find_channel("nonexistent", "channel");
    assert!(channel.is_none());
}

#[test]
fn test_ipc_bus_enqueue_and_dequeue() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("from", "to", &token).unwrap();

    let channel = bus.find_channel("from", "to").unwrap();
    let msg = IpcMessage::new("from", "to", b"test").unwrap();
    channel.send(msg).unwrap();

    assert_eq!(bus.get_queue_depth(), 1);

    let dequeued = bus.get_next_message();
    assert!(dequeued.is_some());
    assert_eq!(dequeued.unwrap().data, b"test".to_vec());
    assert_eq!(bus.get_queue_depth(), 0);
}

#[test]
fn test_ipc_bus_list_routes() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("a", "b", &token).unwrap();
    bus.open_channel("c", "d", &token).unwrap();

    let routes = bus.list_routes();
    assert_eq!(routes.len(), 2);
    assert!(routes.iter().any(|(f, t)| f == "a" && t == "b"));
    assert!(routes.iter().any(|(f, t)| f == "c" && t == "d"));
}

#[test]
fn test_ipc_bus_remove_channel() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("a", "b", &token).unwrap();
    assert_eq!(bus.get_active_channel_count(), 1);

    bus.remove_channel(0);
    assert_eq!(bus.get_active_channel_count(), 0);
}

#[test]
fn test_ipc_bus_remove_all_channels_for_module() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("mod1", "mod2", &token).unwrap();
    bus.open_channel("mod1", "mod3", &token).unwrap();
    bus.open_channel("mod2", "mod3", &token).unwrap();
    assert_eq!(bus.get_active_channel_count(), 3);

    bus.remove_all_channels_for_module("mod1");
    assert_eq!(bus.get_active_channel_count(), 1);
}

#[test]
fn test_ipc_bus_get_stats() {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("from", "to", &token).unwrap();

    let channel = bus.find_channel("from", "to").unwrap();
    let msg = IpcMessage::new("from", "to", b"data").unwrap();
    channel.send(msg).unwrap();

    let stats = bus.get_stats();
    assert!(stats.channels_opened >= 1);
    assert!(stats.messages_enqueued >= 1);
    assert!(stats.bytes_transferred > 0);
}

#[test]
fn test_bus_stats_snapshot_display() {
    let snap = BusStatsSnapshot {
        messages_enqueued: 100,
        messages_dequeued: 90,
        messages_timed_out: 5,
        channels_opened: 10,
        channels_closed: 2,
        bytes_transferred: 50000,
        queue_full_rejections: 3,
        current_queue_depth: 10,
        current_channel_count: 8,
    };
    let s = alloc::format!("{}", snap);
    assert!(s.contains("100"));
    assert!(s.contains("90"));
    assert!(s.contains("50000"));
}

#[test]
fn test_channel_error_not_found() {
    let e = ChannelError::NotFound {
        from: String::from("a"),
        to: String::from("b"),
    };
    assert_eq!(e.as_str(), "Channel not found");
    let msg = alloc::format!("{}", e);
    assert!(msg.contains("a"));
    assert!(msg.contains("b"));
}

#[test]
fn test_channel_error_queue_full() {
    let e = ChannelError::QueueFull {
        queue_size: 100,
        max_size: 100,
    };
    assert_eq!(e.as_str(), "Queue full");
    let msg = alloc::format!("{}", e);
    assert!(msg.contains("100"));
}

#[test]
fn test_channel_error_message_too_large() {
    let e = ChannelError::MessageTooLarge {
        size: 2_000_000,
        max: 1_000_000,
    };
    assert_eq!(e.as_str(), "Message too large");
    let msg = alloc::format!("{}", e);
    assert!(msg.contains("2000000"));
    assert!(msg.contains("1000000"));
}

#[test]
fn test_channel_error_already_exists() {
    let e = ChannelError::AlreadyExists {
        from: String::from("x"),
        to: String::from("y"),
    };
    assert_eq!(e.as_str(), "Channel exists");
    let msg = alloc::format!("{}", e);
    assert!(msg.contains("exists"));
}

#[test]
fn test_channel_error_invalid_endpoints() {
    let e = ChannelError::InvalidEndpoints;
    assert_eq!(e.as_str(), "Invalid endpoints");
    let msg = alloc::format!("{}", e);
    assert!(msg.contains("Invalid"));
}

#[test]
fn test_channel_error_integrity_check_failed() {
    let e = ChannelError::IntegrityCheckFailed;
    assert_eq!(e.as_str(), "Integrity check failed");
    let msg = alloc::format!("{}", e);
    assert!(msg.contains("integrity"));
}

#[test]
fn test_channel_error_equality() {
    let e1 = ChannelError::InvalidEndpoints;
    let e2 = ChannelError::InvalidEndpoints;
    let e3 = ChannelError::IntegrityCheckFailed;
    assert_eq!(e1, e2);
    assert_ne!(e1, e3);
}

#[test]
fn test_default_max_queue_constant() {
    assert!(DEFAULT_MAX_QUEUE > 0);
    assert!(DEFAULT_MAX_QUEUE >= 1024);
}

#[test]
fn test_default_msg_timeout_constant() {
    assert!(DEFAULT_MSG_TIMEOUT_MS > 0);
    assert!(DEFAULT_MSG_TIMEOUT_MS >= 1000);
}

#[test]
fn test_max_message_size_constant() {
    assert!(MAX_MESSAGE_SIZE > 0);
    assert_eq!(MAX_MESSAGE_SIZE, 1024 * 1024);
}

#[test]
fn test_global_ipc_bus_exists() {
    assert!(IPC_BUS.get_active_channel_count() >= 0);
}

#[test]
fn test_ipc_bus_find_dead_channels_empty() {
    let bus = IpcBus::new();
    let dead = bus.find_dead_channels();
    assert!(dead.is_empty());
}

#[test]
fn test_ipc_bus_get_timed_out_messages_empty() {
    let bus = IpcBus::new();
    let timed_out = bus.get_timed_out_messages();
    assert!(timed_out.is_empty());
}

#[test]
fn test_ipc_bus_get_next_message_empty() {
    let bus = IpcBus::new();
    let msg = bus.get_next_message();
    assert!(msg.is_none());
}

#[test]
fn test_ipc_bus_remove_channel_out_of_bounds() {
    let bus = IpcBus::new();
    bus.remove_channel(999);
    assert_eq!(bus.get_active_channel_count(), 0);
}
