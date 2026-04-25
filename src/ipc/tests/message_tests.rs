// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::channel::{IpcMessage, MAX_MESSAGE_SIZE};
use crate::ipc::message::{
    EnvelopeBuilder, IpcEnvelope, MessageError, MessageType, SecurityLevel, MAX_PAYLOAD_SIZE,
};
use crate::test::framework::TestResult;
use alloc::vec;

pub(crate) fn test_security_level_none() -> TestResult {
    let level = SecurityLevel::None;
    if level.as_str() != "None" {
        return TestResult::Fail;
    }
    if level.is_protected() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_signed() -> TestResult {
    let level = SecurityLevel::Signed;
    if level.as_str() != "Signed" {
        return TestResult::Fail;
    }
    if !level.is_protected() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_encrypted() -> TestResult {
    let level = SecurityLevel::Encrypted;
    if level.as_str() != "Encrypted" {
        return TestResult::Fail;
    }
    if !level.is_protected() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_ordering() -> TestResult {
    if !(SecurityLevel::Encrypted > SecurityLevel::Signed) {
        return TestResult::Fail;
    }
    if !(SecurityLevel::Signed > SecurityLevel::None) {
        return TestResult::Fail;
    }
    if !(SecurityLevel::Encrypted > SecurityLevel::None) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_meets_requirement_none() -> TestResult {
    if !SecurityLevel::None.meets_requirement(SecurityLevel::None) {
        return TestResult::Fail;
    }
    if SecurityLevel::None.meets_requirement(SecurityLevel::Signed) {
        return TestResult::Fail;
    }
    if SecurityLevel::None.meets_requirement(SecurityLevel::Encrypted) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_meets_requirement_signed() -> TestResult {
    if !SecurityLevel::Signed.meets_requirement(SecurityLevel::None) {
        return TestResult::Fail;
    }
    if !SecurityLevel::Signed.meets_requirement(SecurityLevel::Signed) {
        return TestResult::Fail;
    }
    if SecurityLevel::Signed.meets_requirement(SecurityLevel::Encrypted) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_meets_requirement_encrypted() -> TestResult {
    if !SecurityLevel::Encrypted.meets_requirement(SecurityLevel::None) {
        return TestResult::Fail;
    }
    if !SecurityLevel::Encrypted.meets_requirement(SecurityLevel::Signed) {
        return TestResult::Fail;
    }
    if !SecurityLevel::Encrypted.meets_requirement(SecurityLevel::Encrypted) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_default() -> TestResult {
    let level = SecurityLevel::default();
    if level != SecurityLevel::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_clone() -> TestResult {
    let level = SecurityLevel::Encrypted;
    let cloned = level.clone();
    if level != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_copy() -> TestResult {
    let level = SecurityLevel::Signed;
    let copied = level;
    if level != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_equality() -> TestResult {
    if SecurityLevel::None != SecurityLevel::None {
        return TestResult::Fail;
    }
    if SecurityLevel::None == SecurityLevel::Signed {
        return TestResult::Fail;
    }
    if SecurityLevel::Signed == SecurityLevel::Encrypted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_debug() -> TestResult {
    let level = SecurityLevel::Encrypted;
    let debug_str = alloc::format!("{:?}", level);
    if !debug_str.contains("Encrypted") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_display() -> TestResult {
    if alloc::format!("{}", SecurityLevel::None) != "None" {
        return TestResult::Fail;
    }
    if alloc::format!("{}", SecurityLevel::Signed) != "Signed" {
        return TestResult::Fail;
    }
    if alloc::format!("{}", SecurityLevel::Encrypted) != "Encrypted" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_data() -> TestResult {
    let mt = MessageType::Data;
    if mt.as_str() != "Data" {
        return TestResult::Fail;
    }
    if mt.is_notification() {
        return TestResult::Fail;
    }
    if mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_control() -> TestResult {
    let mt = MessageType::Control;
    if mt.as_str() != "Control" {
        return TestResult::Fail;
    }
    if mt.is_notification() {
        return TestResult::Fail;
    }
    if mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_timeout() -> TestResult {
    let mt = MessageType::Timeout;
    if mt.as_str() != "Timeout" {
        return TestResult::Fail;
    }
    if !mt.is_notification() {
        return TestResult::Fail;
    }
    if !mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_delivery_failure() -> TestResult {
    let mt = MessageType::DeliveryFailure;
    if mt.as_str() != "DeliveryFailure" {
        return TestResult::Fail;
    }
    if !mt.is_notification() {
        return TestResult::Fail;
    }
    if !mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_capability_result() -> TestResult {
    let mt = MessageType::CapabilityResult;
    if mt.as_str() != "CapabilityResult" {
        return TestResult::Fail;
    }
    if mt.is_notification() {
        return TestResult::Fail;
    }
    if mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_error() -> TestResult {
    let mt = MessageType::Error;
    if mt.as_str() != "Error" {
        return TestResult::Fail;
    }
    if !mt.is_notification() {
        return TestResult::Fail;
    }
    if !mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_ack() -> TestResult {
    let mt = MessageType::Ack;
    if mt.as_str() != "Ack" {
        return TestResult::Fail;
    }
    if !mt.is_notification() {
        return TestResult::Fail;
    }
    if mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_request() -> TestResult {
    let mt = MessageType::Request;
    if mt.as_str() != "Request" {
        return TestResult::Fail;
    }
    if mt.is_notification() {
        return TestResult::Fail;
    }
    if mt.is_error() {
        return TestResult::Fail;
    }
    if !mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_response() -> TestResult {
    let mt = MessageType::Response;
    if mt.as_str() != "Response" {
        return TestResult::Fail;
    }
    if mt.is_notification() {
        return TestResult::Fail;
    }
    if mt.is_error() {
        return TestResult::Fail;
    }
    if mt.expects_response() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_default() -> TestResult {
    let mt = MessageType::default();
    if mt != MessageType::Data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_clone() -> TestResult {
    let mt = MessageType::Request;
    let cloned = mt.clone();
    if mt != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_copy() -> TestResult {
    let mt = MessageType::Response;
    let copied = mt;
    if mt != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_equality() -> TestResult {
    if MessageType::Data != MessageType::Data {
        return TestResult::Fail;
    }
    if MessageType::Data == MessageType::Control {
        return TestResult::Fail;
    }
    if MessageType::Request == MessageType::Response {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_debug() -> TestResult {
    let mt = MessageType::Request;
    let debug_str = alloc::format!("{:?}", mt);
    if !debug_str.contains("Request") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_display() -> TestResult {
    if alloc::format!("{}", MessageType::Data) != "Data" {
        return TestResult::Fail;
    }
    if alloc::format!("{}", MessageType::Error) != "Error" {
        return TestResult::Fail;
    }
    if alloc::format!("{}", MessageType::Request) != "Request" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_empty_source() -> TestResult {
    let err = MessageError::EmptySource;
    if err.as_str() != "Source address is empty" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_empty_destination() -> TestResult {
    let err = MessageError::EmptyDestination;
    if err.as_str() != "Destination address is empty" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_payload_too_large() -> TestResult {
    let err = MessageError::PayloadTooLarge { size: 100, max: 50 };
    if err.as_str() != "Payload exceeds maximum size" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_invalid_session_id() -> TestResult {
    let err = MessageError::InvalidSessionId;
    if err.as_str() != "Invalid session ID" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_security_level_mismatch() -> TestResult {
    let err = MessageError::SecurityLevelMismatch {
        required: SecurityLevel::Encrypted,
        actual: SecurityLevel::None,
    };
    if err.as_str() != "Security level mismatch" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_display_empty_source() -> TestResult {
    let err = MessageError::EmptySource;
    let display = alloc::format!("{}", err);
    if !display.contains("empty") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_display_payload_too_large() -> TestResult {
    let err = MessageError::PayloadTooLarge { size: 200, max: 100 };
    let display = alloc::format!("{}", err);
    if !display.contains("200") {
        return TestResult::Fail;
    }
    if !display.contains("100") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_display_security_mismatch() -> TestResult {
    let err = MessageError::SecurityLevelMismatch {
        required: SecurityLevel::Signed,
        actual: SecurityLevel::None,
    };
    let display = alloc::format!("{}", err);
    if !display.contains("Signed") {
        return TestResult::Fail;
    }
    if !display.contains("None") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_clone() -> TestResult {
    let err = MessageError::EmptySource;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_equality() -> TestResult {
    if MessageError::EmptySource != MessageError::EmptySource {
        return TestResult::Fail;
    }
    if MessageError::EmptySource == MessageError::EmptyDestination {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_new() -> TestResult {
    let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    if env.from != "sender" {
        return TestResult::Fail;
    }
    if env.to != "receiver" {
        return TestResult::Fail;
    }
    if env.message_type != MessageType::Data {
        return TestResult::Fail;
    }
    if env.data != vec![1, 2, 3] {
        return TestResult::Fail;
    }
    if env.session_id.is_some() {
        return TestResult::Fail;
    }
    if env.sec_level != SecurityLevel::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_len() -> TestResult {
    let env = IpcEnvelope::new("a", "b", MessageType::Data, vec![1, 2, 3, 4, 5]);
    if env.len() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_is_empty() -> TestResult {
    let env = IpcEnvelope::new("a", "b", MessageType::Data, vec![]);
    if !env.is_empty() {
        return TestResult::Fail;
    }

    let env2 = IpcEnvelope::new("a", "b", MessageType::Data, vec![1]);
    if env2.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_total_size() -> TestResult {
    let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    let total = env.total_size();
    if !(total >= env.from.len() + env.to.len() + env.data.len()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_validate_success() -> TestResult {
    let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    if env.validate().is_err() {
        return TestResult::Fail;
    }
    if !env.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_validate_empty_source() -> TestResult {
    let env = IpcEnvelope::new("", "receiver", MessageType::Data, vec![]);
    if !matches!(env.validate(), Err(MessageError::EmptySource)) {
        return TestResult::Fail;
    }
    if env.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_validate_empty_destination() -> TestResult {
    let env = IpcEnvelope::new("sender", "", MessageType::Data, vec![]);
    if !matches!(env.validate(), Err(MessageError::EmptyDestination)) {
        return TestResult::Fail;
    }
    if env.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_default() -> TestResult {
    let env = IpcEnvelope::default();
    if !env.from.is_empty() {
        return TestResult::Fail;
    }
    if !env.to.is_empty() {
        return TestResult::Fail;
    }
    if env.message_type != MessageType::Data {
        return TestResult::Fail;
    }
    if !env.data.is_empty() {
        return TestResult::Fail;
    }
    if env.session_id.is_some() {
        return TestResult::Fail;
    }
    if env.sec_level != SecurityLevel::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_create_response() -> TestResult {
    let mut request = IpcEnvelope::new("client", "server", MessageType::Request, vec![1, 2]);
    request.session_id = Some(42);
    request.sec_level = SecurityLevel::Signed;

    let response = request.create_response(vec![3, 4, 5]);
    if response.from != "server" {
        return TestResult::Fail;
    }
    if response.to != "client" {
        return TestResult::Fail;
    }
    if response.message_type != MessageType::Response {
        return TestResult::Fail;
    }
    if response.data != vec![3, 4, 5] {
        return TestResult::Fail;
    }
    if response.session_id != Some(42) {
        return TestResult::Fail;
    }
    if response.sec_level != SecurityLevel::Signed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_create_error_response() -> TestResult {
    let mut request = IpcEnvelope::new("client", "server", MessageType::Request, vec![1]);
    request.session_id = Some(100);

    let error_response = request.create_error_response(vec![0xFF]);
    if error_response.from != "server" {
        return TestResult::Fail;
    }
    if error_response.to != "client" {
        return TestResult::Fail;
    }
    if error_response.message_type != MessageType::Error {
        return TestResult::Fail;
    }
    if error_response.data != vec![0xFF] {
        return TestResult::Fail;
    }
    if error_response.session_id != Some(100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_create_ack() -> TestResult {
    let msg = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    let ack = msg.create_ack();
    if ack.from != "receiver" {
        return TestResult::Fail;
    }
    if ack.to != "sender" {
        return TestResult::Fail;
    }
    if ack.message_type != MessageType::Ack {
        return TestResult::Fail;
    }
    if !ack.data.is_empty() {
        return TestResult::Fail;
    }
    if ack.sec_level != SecurityLevel::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_envelope_clone() -> TestResult {
    let env = IpcEnvelope::new("a", "b", MessageType::Request, vec![42]);
    let cloned = env.clone();
    if env.from != cloned.from {
        return TestResult::Fail;
    }
    if env.to != cloned.to {
        return TestResult::Fail;
    }
    if env.data != cloned.data {
        return TestResult::Fail;
    }
    if env.message_type != cloned.message_type {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_new() -> TestResult {
    let builder = EnvelopeBuilder::new("from", "to");
    let env = builder.build();
    if env.from != "from" {
        return TestResult::Fail;
    }
    if env.to != "to" {
        return TestResult::Fail;
    }
    if env.message_type != MessageType::Data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_message_type() -> TestResult {
    let env = EnvelopeBuilder::new("a", "b").message_type(MessageType::Request).build();
    if env.message_type != MessageType::Request {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_data() -> TestResult {
    let env = EnvelopeBuilder::new("a", "b").data(vec![1, 2, 3, 4]).build();
    if env.data != vec![1, 2, 3, 4] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_data_from_slice() -> TestResult {
    let data = [10, 20, 30];
    let env = EnvelopeBuilder::new("a", "b").data_from_slice(&data).build();
    if env.data != vec![10, 20, 30] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_session_id() -> TestResult {
    let env = EnvelopeBuilder::new("a", "b").session_id(12345).build();
    if env.session_id != Some(12345) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_security_level() -> TestResult {
    let env = EnvelopeBuilder::new("a", "b").security_level(SecurityLevel::Encrypted).build();
    if env.sec_level != SecurityLevel::Encrypted {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_chained() -> TestResult {
    let env = EnvelopeBuilder::new("client", "server")
        .message_type(MessageType::Request)
        .data(vec![0x42])
        .session_id(999)
        .security_level(SecurityLevel::Signed)
        .build();

    if env.from != "client" {
        return TestResult::Fail;
    }
    if env.to != "server" {
        return TestResult::Fail;
    }
    if env.message_type != MessageType::Request {
        return TestResult::Fail;
    }
    if env.data != vec![0x42] {
        return TestResult::Fail;
    }
    if env.session_id != Some(999) {
        return TestResult::Fail;
    }
    if env.sec_level != SecurityLevel::Signed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_build_validated_success() -> TestResult {
    let result = EnvelopeBuilder::new("sender", "receiver").data(vec![1, 2, 3]).build_validated();
    if result.is_err() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_build_validated_empty_source() -> TestResult {
    let result = EnvelopeBuilder::new("", "receiver").build_validated();
    if !matches!(result, Err(MessageError::EmptySource)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_builder_build_validated_empty_dest() -> TestResult {
    let result = EnvelopeBuilder::new("sender", "").build_validated();
    if !matches!(result, Err(MessageError::EmptyDestination)) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_with_timestamp() -> TestResult {
    let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
    if msg.from != "sender" {
        return TestResult::Fail;
    }
    if msg.to != "receiver" {
        return TestResult::Fail;
    }
    if msg.data != b"hello".to_vec() {
        return TestResult::Fail;
    }
    if msg.timestamp_ms != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_validate_integrity() -> TestResult {
    let msg = IpcMessage::with_timestamp("a", "b", b"test data", 12345);
    if !msg.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_payload_size() -> TestResult {
    let msg = IpcMessage::with_timestamp("a", "b", b"hello", 0);
    if msg.payload_size() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_is_empty() -> TestResult {
    let msg = IpcMessage::with_timestamp("a", "b", b"", 0);
    if !msg.is_empty() {
        return TestResult::Fail;
    }

    let msg2 = IpcMessage::with_timestamp("a", "b", b"x", 0);
    if msg2.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_display() -> TestResult {
    let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
    let display = alloc::format!("{}", msg);
    if !display.contains("sender") {
        return TestResult::Fail;
    }
    if !display.contains("receiver") {
        return TestResult::Fail;
    }
    if !display.contains("5 bytes") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ipc_message_clone() -> TestResult {
    let msg = IpcMessage::with_timestamp("a", "b", b"data", 500);
    let cloned = msg.clone();
    if msg.from != cloned.from {
        return TestResult::Fail;
    }
    if msg.to != cloned.to {
        return TestResult::Fail;
    }
    if msg.data != cloned.data {
        return TestResult::Fail;
    }
    if msg.timestamp_ms != cloned.timestamp_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_payload_size_constant() -> TestResult {
    if MAX_PAYLOAD_SIZE != 16 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_message_size_constant() -> TestResult {
    if MAX_MESSAGE_SIZE != 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_security_level_all_variants_have_str() -> TestResult {
    let levels = [SecurityLevel::None, SecurityLevel::Signed, SecurityLevel::Encrypted];
    for level in levels {
        if level.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_message_type_all_variants_have_str() -> TestResult {
    let types = [
        MessageType::Data,
        MessageType::Control,
        MessageType::Timeout,
        MessageType::DeliveryFailure,
        MessageType::CapabilityResult,
        MessageType::Error,
        MessageType::Ack,
        MessageType::Request,
        MessageType::Response,
    ];
    for mt in types {
        if mt.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_message_error_all_variants_have_str() -> TestResult {
    let errors = [
        MessageError::EmptySource,
        MessageError::EmptyDestination,
        MessageError::PayloadTooLarge { size: 0, max: 0 },
        MessageError::InvalidSessionId,
        MessageError::SecurityLevelMismatch {
            required: SecurityLevel::None,
            actual: SecurityLevel::None,
        },
    ];
    for err in errors {
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_with_various_data_sizes() -> TestResult {
    let empty = IpcEnvelope::new("a", "b", MessageType::Data, vec![]);
    if !empty.is_empty() {
        return TestResult::Fail;
    }
    if !empty.is_valid() {
        return TestResult::Fail;
    }

    let small = IpcEnvelope::new("a", "b", MessageType::Data, vec![1; 10]);
    if small.len() != 10 {
        return TestResult::Fail;
    }
    if !small.is_valid() {
        return TestResult::Fail;
    }

    let medium = IpcEnvelope::new("a", "b", MessageType::Data, vec![2; 1000]);
    if medium.len() != 1000 {
        return TestResult::Fail;
    }
    if !medium.is_valid() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_response_preserves_session() -> TestResult {
    let mut req = IpcEnvelope::new("a", "b", MessageType::Request, vec![]);
    req.session_id = Some(0xDEADBEEF);

    let resp = req.create_response(vec![]);
    if resp.session_id != Some(0xDEADBEEF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_envelope_error_response_preserves_session() -> TestResult {
    let mut req = IpcEnvelope::new("a", "b", MessageType::Request, vec![]);
    req.session_id = Some(0xCAFEBABE);

    let err_resp = req.create_error_response(vec![]);
    if err_resp.session_id != Some(0xCAFEBABE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_integrity_different_data() -> TestResult {
    let msg1 = IpcMessage::with_timestamp("a", "b", b"data1", 1000);
    let msg2 = IpcMessage::with_timestamp("a", "b", b"data2", 1000);
    if !msg1.validate_integrity() {
        return TestResult::Fail;
    }
    if !msg2.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_integrity_different_timestamps() -> TestResult {
    let msg1 = IpcMessage::with_timestamp("a", "b", b"data", 1000);
    let msg2 = IpcMessage::with_timestamp("a", "b", b"data", 2000);
    if !msg1.validate_integrity() {
        return TestResult::Fail;
    }
    if !msg2.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_message_integrity_different_endpoints() -> TestResult {
    let msg1 = IpcMessage::with_timestamp("a", "b", b"data", 1000);
    let msg2 = IpcMessage::with_timestamp("x", "y", b"data", 1000);
    if !msg1.validate_integrity() {
        return TestResult::Fail;
    }
    if !msg2.validate_integrity() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
