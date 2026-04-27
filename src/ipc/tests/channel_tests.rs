use crate::ipc::nonos_channel::{
    compute_channel_key, compute_checksum, init_ipc_secret, BusStatsSnapshot, ChannelError, IpcBus,
    IpcMessage, DEFAULT_MAX_QUEUE, DEFAULT_MSG_TIMEOUT_MS, MAX_MESSAGE_SIZE,
};
use crate::ipc::*;
use crate::syscall::capabilities::CapabilityToken;
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;

pub(crate) fn test_ipc_message_creation() -> TestResult {
    let msg = IpcMessage::new("sender", "receiver", b"hello world");
    if msg.is_err() {
        return TestResult::Fail;
    }
    let msg = msg.unwrap();
    if msg.from != "sender" {
        return TestResult::Fail;
    }
    if msg.to != "receiver" {
        return TestResult::Fail;
    }
    if msg.data != b"hello world".to_vec() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_empty_payload() -> TestResult {
    let msg = IpcMessage::new("a", "b", &[]);
    if msg.is_err() {
        return TestResult::Fail;
    }
    let msg = msg.unwrap();
    if !msg.is_empty() {
        return TestResult::Fail;
    }
    if msg.payload_size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_payload_size() -> TestResult {
    let msg = IpcMessage::new("a", "b", b"test payload").unwrap();
    if msg.payload_size() != 12 {
        return TestResult::Fail;
    }
    if msg.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_validate_integrity() -> TestResult {
    let msg = IpcMessage::new("sender", "receiver", b"data").unwrap();
    if !msg.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_with_timestamp() -> TestResult {
    let msg = IpcMessage::with_timestamp("a", "b", b"test", 12345);
    if msg.timestamp_ms != 12345 {
        return TestResult::Fail;
    }
    if !msg.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_size_limit_exceeded() -> TestResult {
    let large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
    let result = IpcMessage::new("a", "b", &large_data);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_size_limit_at_boundary() -> TestResult {
    let boundary_data = vec![0u8; MAX_MESSAGE_SIZE];
    let result = IpcMessage::new("a", "b", &boundary_data);
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_display() -> TestResult {
    let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
    let s = alloc::format!("{}", msg);
    if !s.contains("sender") {
        return TestResult::Fail;
    }
    if !s.contains("receiver") {
        return TestResult::Fail;
    }
    if !s.contains("5 bytes") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_clone() -> TestResult {
    let msg = IpcMessage::new("a", "b", b"data").unwrap();
    let cloned = msg.clone();
    if cloned.from != msg.from {
        return TestResult::Fail;
    }
    if cloned.to != msg.to {
        return TestResult::Fail;
    }
    if cloned.data != msg.data {
        return TestResult::Fail;
    }
    if !cloned.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_channel_key() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("test_key_from", "test_key_to", &token).unwrap();
    let channel = bus.find_channel("test_key_from", "test_key_to").unwrap();
    if channel.key() == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_channel_debug() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("debug_from", "debug_to", &token).unwrap();
    let channel = bus.find_channel("debug_from", "debug_to").unwrap();
    let s = alloc::format!("{:?}", channel);
    if !s.contains("IpcChannel") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_channel_copy() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("copy_from", "copy_to", &token).unwrap();
    let channel = bus.find_channel("copy_from", "copy_to").unwrap();
    let key = channel.key();
    if key == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_channel_key_consistency() -> TestResult {
    let key1 = compute_channel_key("from", "to");
    let key2 = compute_channel_key("from", "to");
    if key1 != key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_channel_key_different_endpoints() -> TestResult {
    let key1 = compute_channel_key("from1", "to1");
    let key2 = compute_channel_key("from2", "to2");
    if key1 == key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_channel_key_order_matters() -> TestResult {
    let key1 = compute_channel_key("a", "b");
    let key2 = compute_channel_key("b", "a");
    if key1 == key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_checksum_consistency() -> TestResult {
    let csum1 = compute_checksum("from", "to", b"data", 1000);
    let csum2 = compute_checksum("from", "to", b"data", 1000);
    if csum1 != csum2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_checksum_different_data() -> TestResult {
    let csum1 = compute_checksum("from", "to", b"data1", 1000);
    let csum2 = compute_checksum("from", "to", b"data2", 1000);
    if csum1 == csum2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_compute_checksum_different_timestamp() -> TestResult {
    let csum1 = compute_checksum("from", "to", b"data", 1000);
    let csum2 = compute_checksum("from", "to", b"data", 2000);
    if csum1 == csum2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_init_ipc_secret_idempotent() -> TestResult {
    init_ipc_secret();
    let key1 = compute_channel_key("test", "secret");
    init_ipc_secret();
    let key2 = compute_channel_key("test", "secret");
    if key1 != key2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_new() -> TestResult {
    let bus = IpcBus::new();
    if bus.get_active_channel_count() != 0 {
        return TestResult::Fail;
    }
    if bus.get_queue_depth() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_channel_exists() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("from", "to", &token).unwrap();
    if !bus.channel_exists("from", "to") {
        return TestResult::Fail;
    }
    if bus.channel_exists("nonexistent", "channel") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_open_channel_idempotent() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("a", "b", &token).unwrap();
    bus.open_channel("a", "b", &token).unwrap();
    if bus.get_active_channel_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_open_channel_empty_endpoints() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    let result = bus.open_channel("", "to", &token);
    if result.is_ok() {
        return TestResult::Fail;
    }

    let result = bus.open_channel("from", "", &token);
    if result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_find_channel() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("sender", "receiver", &token).unwrap();

    let channel = bus.find_channel("sender", "receiver");
    if channel.is_none() {
        return TestResult::Fail;
    }

    let channel = bus.find_channel("nonexistent", "channel");
    if channel.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_enqueue_and_dequeue() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("from", "to", &token).unwrap();

    let channel = bus.find_channel("from", "to").unwrap();
    let msg = IpcMessage::new("from", "to", b"test").unwrap();
    channel.send(msg).unwrap();

    if bus.get_queue_depth() != 1 {
        return TestResult::Fail;
    }

    let dequeued = bus.get_next_message();
    if dequeued.is_none() {
        return TestResult::Fail;
    }
    if dequeued.unwrap().data != b"test".to_vec() {
        return TestResult::Fail;
    }
    if bus.get_queue_depth() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_list_routes() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("a", "b", &token).unwrap();
    bus.open_channel("c", "d", &token).unwrap();

    let routes = bus.list_routes();
    if routes.len() != 2 {
        return TestResult::Fail;
    }
    if !routes.iter().any(|(f, t)| f == "a" && t == "b") {
        return TestResult::Fail;
    }
    if !routes.iter().any(|(f, t)| f == "c" && t == "d") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_remove_channel() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("a", "b", &token).unwrap();
    if bus.get_active_channel_count() != 1 {
        return TestResult::Fail;
    }

    bus.remove_channel(0);
    if bus.get_active_channel_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_remove_all_channels_for_module() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("mod1", "mod2", &token).unwrap();
    bus.open_channel("mod1", "mod3", &token).unwrap();
    bus.open_channel("mod2", "mod3", &token).unwrap();
    if bus.get_active_channel_count() != 3 {
        return TestResult::Fail;
    }

    bus.remove_all_channels_for_module("mod1");
    if bus.get_active_channel_count() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_get_stats() -> TestResult {
    let bus = IpcBus::new();
    let token = CapabilityToken::system();
    bus.open_channel("from", "to", &token).unwrap();

    let channel = bus.find_channel("from", "to").unwrap();
    let msg = IpcMessage::new("from", "to", b"data").unwrap();
    channel.send(msg).unwrap();

    let stats = bus.get_stats();
    if stats.channels_opened < 1 {
        return TestResult::Fail;
    }
    if stats.messages_enqueued < 1 {
        return TestResult::Fail;
    }
    if stats.bytes_transferred <= 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bus_stats_snapshot_display() -> TestResult {
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
    if !s.contains("100") {
        return TestResult::Fail;
    }
    if !s.contains("90") {
        return TestResult::Fail;
    }
    if !s.contains("50000") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_not_found() -> TestResult {
    let e = ChannelError::NotFound { from: String::from("a"), to: String::from("b") };
    if e.as_str() != "Channel not found" {
        return TestResult::Fail;
    }
    let msg = alloc::format!("{}", e);
    if !msg.contains("a") {
        return TestResult::Fail;
    }
    if !msg.contains("b") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_queue_full() -> TestResult {
    let e = ChannelError::QueueFull { queue_size: 100, max_size: 100 };
    if e.as_str() != "Queue full" {
        return TestResult::Fail;
    }
    let msg = alloc::format!("{}", e);
    if !msg.contains("100") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_message_too_large() -> TestResult {
    let e = ChannelError::MessageTooLarge { size: 2_000_000, max: 1_000_000 };
    if e.as_str() != "Message too large" {
        return TestResult::Fail;
    }
    let msg = alloc::format!("{}", e);
    if !msg.contains("2000000") {
        return TestResult::Fail;
    }
    if !msg.contains("1000000") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_already_exists() -> TestResult {
    let e = ChannelError::AlreadyExists { from: String::from("x"), to: String::from("y") };
    if e.as_str() != "Channel exists" {
        return TestResult::Fail;
    }
    let msg = alloc::format!("{}", e);
    if !msg.contains("exists") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_invalid_endpoints() -> TestResult {
    let e = ChannelError::InvalidEndpoints;
    if e.as_str() != "Invalid endpoints" {
        return TestResult::Fail;
    }
    let msg = alloc::format!("{}", e);
    if !msg.contains("Invalid") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_integrity_check_failed() -> TestResult {
    let e = ChannelError::IntegrityCheckFailed;
    if e.as_str() != "Integrity check failed" {
        return TestResult::Fail;
    }
    let msg = alloc::format!("{}", e);
    if !msg.contains("integrity") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_channel_error_equality() -> TestResult {
    let e1 = ChannelError::InvalidEndpoints;
    let e2 = ChannelError::InvalidEndpoints;
    let e3 = ChannelError::IntegrityCheckFailed;
    if e1 != e2 {
        return TestResult::Fail;
    }
    if e1 == e3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_max_queue_constant() -> TestResult {
    if DEFAULT_MAX_QUEUE <= 0 {
        return TestResult::Fail;
    }
    if DEFAULT_MAX_QUEUE < 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_msg_timeout_constant() -> TestResult {
    if DEFAULT_MSG_TIMEOUT_MS <= 0 {
        return TestResult::Fail;
    }
    if DEFAULT_MSG_TIMEOUT_MS < 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_message_size_constant() -> TestResult {
    if MAX_MESSAGE_SIZE <= 0 {
        return TestResult::Fail;
    }
    if MAX_MESSAGE_SIZE != 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_global_ipc_bus_exists() -> TestResult {
    let _ = IPC_BUS.get_active_channel_count();
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_find_dead_channels_empty() -> TestResult {
    let bus = IpcBus::new();
    let dead = bus.find_dead_channels();
    if !dead.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_get_timed_out_messages_empty() -> TestResult {
    let bus = IpcBus::new();
    let timed_out = bus.get_timed_out_messages();
    if !timed_out.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_get_next_message_empty() -> TestResult {
    let bus = IpcBus::new();
    let msg = bus.get_next_message();
    if msg.is_some() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_bus_remove_channel_out_of_bounds() -> TestResult {
    let bus = IpcBus::new();
    bus.remove_channel(999);
    if bus.get_active_channel_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
