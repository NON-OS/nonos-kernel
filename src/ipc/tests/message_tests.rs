// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::ipc::nonos_message::types::{SecurityLevel, MessageType, MessageError};
use crate::ipc::nonos_message::envelope::{IpcEnvelope, MAX_PAYLOAD_SIZE};
use crate::ipc::nonos_message::builder::EnvelopeBuilder;
use crate::ipc::nonos_channel::message::{IpcMessage, MAX_MESSAGE_SIZE};
use alloc::vec;
use alloc::string::String;

#[test]
fn test_security_level_none() {
    let level = SecurityLevel::None;
    assert_eq!(level.as_str(), "None");
    assert!(!level.is_protected());
}

#[test]
fn test_security_level_signed() {
    let level = SecurityLevel::Signed;
    assert_eq!(level.as_str(), "Signed");
    assert!(level.is_protected());
}

#[test]
fn test_security_level_encrypted() {
    let level = SecurityLevel::Encrypted;
    assert_eq!(level.as_str(), "Encrypted");
    assert!(level.is_protected());
}

#[test]
fn test_security_level_ordering() {
    assert!(SecurityLevel::Encrypted > SecurityLevel::Signed);
    assert!(SecurityLevel::Signed > SecurityLevel::None);
    assert!(SecurityLevel::Encrypted > SecurityLevel::None);
}

#[test]
fn test_security_level_meets_requirement_none() {
    assert!(SecurityLevel::None.meets_requirement(SecurityLevel::None));
    assert!(!SecurityLevel::None.meets_requirement(SecurityLevel::Signed));
    assert!(!SecurityLevel::None.meets_requirement(SecurityLevel::Encrypted));
}

#[test]
fn test_security_level_meets_requirement_signed() {
    assert!(SecurityLevel::Signed.meets_requirement(SecurityLevel::None));
    assert!(SecurityLevel::Signed.meets_requirement(SecurityLevel::Signed));
    assert!(!SecurityLevel::Signed.meets_requirement(SecurityLevel::Encrypted));
}

#[test]
fn test_security_level_meets_requirement_encrypted() {
    assert!(SecurityLevel::Encrypted.meets_requirement(SecurityLevel::None));
    assert!(SecurityLevel::Encrypted.meets_requirement(SecurityLevel::Signed));
    assert!(SecurityLevel::Encrypted.meets_requirement(SecurityLevel::Encrypted));
}

#[test]
fn test_security_level_default() {
    let level = SecurityLevel::default();
    assert_eq!(level, SecurityLevel::None);
}

#[test]
fn test_security_level_clone() {
    let level = SecurityLevel::Encrypted;
    let cloned = level.clone();
    assert_eq!(level, cloned);
}

#[test]
fn test_security_level_copy() {
    let level = SecurityLevel::Signed;
    let copied = level;
    assert_eq!(level, copied);
}

#[test]
fn test_security_level_equality() {
    assert_eq!(SecurityLevel::None, SecurityLevel::None);
    assert_ne!(SecurityLevel::None, SecurityLevel::Signed);
    assert_ne!(SecurityLevel::Signed, SecurityLevel::Encrypted);
}

#[test]
fn test_security_level_debug() {
    let level = SecurityLevel::Encrypted;
    let debug_str = alloc::format!("{:?}", level);
    assert!(debug_str.contains("Encrypted"));
}

#[test]
fn test_security_level_display() {
    assert_eq!(alloc::format!("{}", SecurityLevel::None), "None");
    assert_eq!(alloc::format!("{}", SecurityLevel::Signed), "Signed");
    assert_eq!(alloc::format!("{}", SecurityLevel::Encrypted), "Encrypted");
}

#[test]
fn test_message_type_data() {
    let mt = MessageType::Data;
    assert_eq!(mt.as_str(), "Data");
    assert!(!mt.is_notification());
    assert!(!mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_control() {
    let mt = MessageType::Control;
    assert_eq!(mt.as_str(), "Control");
    assert!(!mt.is_notification());
    assert!(!mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_timeout() {
    let mt = MessageType::Timeout;
    assert_eq!(mt.as_str(), "Timeout");
    assert!(mt.is_notification());
    assert!(mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_delivery_failure() {
    let mt = MessageType::DeliveryFailure;
    assert_eq!(mt.as_str(), "DeliveryFailure");
    assert!(mt.is_notification());
    assert!(mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_capability_result() {
    let mt = MessageType::CapabilityResult;
    assert_eq!(mt.as_str(), "CapabilityResult");
    assert!(!mt.is_notification());
    assert!(!mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_error() {
    let mt = MessageType::Error;
    assert_eq!(mt.as_str(), "Error");
    assert!(mt.is_notification());
    assert!(mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_ack() {
    let mt = MessageType::Ack;
    assert_eq!(mt.as_str(), "Ack");
    assert!(mt.is_notification());
    assert!(!mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_request() {
    let mt = MessageType::Request;
    assert_eq!(mt.as_str(), "Request");
    assert!(!mt.is_notification());
    assert!(!mt.is_error());
    assert!(mt.expects_response());
}

#[test]
fn test_message_type_response() {
    let mt = MessageType::Response;
    assert_eq!(mt.as_str(), "Response");
    assert!(!mt.is_notification());
    assert!(!mt.is_error());
    assert!(!mt.expects_response());
}

#[test]
fn test_message_type_default() {
    let mt = MessageType::default();
    assert_eq!(mt, MessageType::Data);
}

#[test]
fn test_message_type_clone() {
    let mt = MessageType::Request;
    let cloned = mt.clone();
    assert_eq!(mt, cloned);
}

#[test]
fn test_message_type_copy() {
    let mt = MessageType::Response;
    let copied = mt;
    assert_eq!(mt, copied);
}

#[test]
fn test_message_type_equality() {
    assert_eq!(MessageType::Data, MessageType::Data);
    assert_ne!(MessageType::Data, MessageType::Control);
    assert_ne!(MessageType::Request, MessageType::Response);
}

#[test]
fn test_message_type_debug() {
    let mt = MessageType::Request;
    let debug_str = alloc::format!("{:?}", mt);
    assert!(debug_str.contains("Request"));
}

#[test]
fn test_message_type_display() {
    assert_eq!(alloc::format!("{}", MessageType::Data), "Data");
    assert_eq!(alloc::format!("{}", MessageType::Error), "Error");
    assert_eq!(alloc::format!("{}", MessageType::Request), "Request");
}

#[test]
fn test_message_error_empty_source() {
    let err = MessageError::EmptySource;
    assert_eq!(err.as_str(), "Source address is empty");
}

#[test]
fn test_message_error_empty_destination() {
    let err = MessageError::EmptyDestination;
    assert_eq!(err.as_str(), "Destination address is empty");
}

#[test]
fn test_message_error_payload_too_large() {
    let err = MessageError::PayloadTooLarge { size: 100, max: 50 };
    assert_eq!(err.as_str(), "Payload exceeds maximum size");
}

#[test]
fn test_message_error_invalid_session_id() {
    let err = MessageError::InvalidSessionId;
    assert_eq!(err.as_str(), "Invalid session ID");
}

#[test]
fn test_message_error_security_level_mismatch() {
    let err = MessageError::SecurityLevelMismatch {
        required: SecurityLevel::Encrypted,
        actual: SecurityLevel::None,
    };
    assert_eq!(err.as_str(), "Security level mismatch");
}

#[test]
fn test_message_error_display_empty_source() {
    let err = MessageError::EmptySource;
    let display = alloc::format!("{}", err);
    assert!(display.contains("empty"));
}

#[test]
fn test_message_error_display_payload_too_large() {
    let err = MessageError::PayloadTooLarge { size: 200, max: 100 };
    let display = alloc::format!("{}", err);
    assert!(display.contains("200"));
    assert!(display.contains("100"));
}

#[test]
fn test_message_error_display_security_mismatch() {
    let err = MessageError::SecurityLevelMismatch {
        required: SecurityLevel::Signed,
        actual: SecurityLevel::None,
    };
    let display = alloc::format!("{}", err);
    assert!(display.contains("Signed"));
    assert!(display.contains("None"));
}

#[test]
fn test_message_error_clone() {
    let err = MessageError::EmptySource;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_message_error_equality() {
    assert_eq!(MessageError::EmptySource, MessageError::EmptySource);
    assert_ne!(MessageError::EmptySource, MessageError::EmptyDestination);
}

#[test]
fn test_ipc_envelope_new() {
    let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    assert_eq!(env.from, "sender");
    assert_eq!(env.to, "receiver");
    assert_eq!(env.message_type, MessageType::Data);
    assert_eq!(env.data, vec![1, 2, 3]);
    assert!(env.session_id.is_none());
    assert_eq!(env.sec_level, SecurityLevel::None);
}

#[test]
fn test_ipc_envelope_len() {
    let env = IpcEnvelope::new("a", "b", MessageType::Data, vec![1, 2, 3, 4, 5]);
    assert_eq!(env.len(), 5);
}

#[test]
fn test_ipc_envelope_is_empty() {
    let env = IpcEnvelope::new("a", "b", MessageType::Data, vec![]);
    assert!(env.is_empty());

    let env2 = IpcEnvelope::new("a", "b", MessageType::Data, vec![1]);
    assert!(!env2.is_empty());
}

#[test]
fn test_ipc_envelope_total_size() {
    let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    let total = env.total_size();
    assert!(total >= env.from.len() + env.to.len() + env.data.len());
}

#[test]
fn test_ipc_envelope_validate_success() {
    let env = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    assert!(env.validate().is_ok());
    assert!(env.is_valid());
}

#[test]
fn test_ipc_envelope_validate_empty_source() {
    let env = IpcEnvelope::new("", "receiver", MessageType::Data, vec![]);
    assert!(matches!(env.validate(), Err(MessageError::EmptySource)));
    assert!(!env.is_valid());
}

#[test]
fn test_ipc_envelope_validate_empty_destination() {
    let env = IpcEnvelope::new("sender", "", MessageType::Data, vec![]);
    assert!(matches!(env.validate(), Err(MessageError::EmptyDestination)));
    assert!(!env.is_valid());
}

#[test]
fn test_ipc_envelope_default() {
    let env = IpcEnvelope::default();
    assert!(env.from.is_empty());
    assert!(env.to.is_empty());
    assert_eq!(env.message_type, MessageType::Data);
    assert!(env.data.is_empty());
    assert!(env.session_id.is_none());
    assert_eq!(env.sec_level, SecurityLevel::None);
}

#[test]
fn test_ipc_envelope_create_response() {
    let mut request = IpcEnvelope::new("client", "server", MessageType::Request, vec![1, 2]);
    request.session_id = Some(42);
    request.sec_level = SecurityLevel::Signed;

    let response = request.create_response(vec![3, 4, 5]);
    assert_eq!(response.from, "server");
    assert_eq!(response.to, "client");
    assert_eq!(response.message_type, MessageType::Response);
    assert_eq!(response.data, vec![3, 4, 5]);
    assert_eq!(response.session_id, Some(42));
    assert_eq!(response.sec_level, SecurityLevel::Signed);
}

#[test]
fn test_ipc_envelope_create_error_response() {
    let mut request = IpcEnvelope::new("client", "server", MessageType::Request, vec![1]);
    request.session_id = Some(100);

    let error_response = request.create_error_response(vec![0xFF]);
    assert_eq!(error_response.from, "server");
    assert_eq!(error_response.to, "client");
    assert_eq!(error_response.message_type, MessageType::Error);
    assert_eq!(error_response.data, vec![0xFF]);
    assert_eq!(error_response.session_id, Some(100));
}

#[test]
fn test_ipc_envelope_create_ack() {
    let msg = IpcEnvelope::new("sender", "receiver", MessageType::Data, vec![1, 2, 3]);
    let ack = msg.create_ack();
    assert_eq!(ack.from, "receiver");
    assert_eq!(ack.to, "sender");
    assert_eq!(ack.message_type, MessageType::Ack);
    assert!(ack.data.is_empty());
    assert_eq!(ack.sec_level, SecurityLevel::None);
}

#[test]
fn test_ipc_envelope_clone() {
    let env = IpcEnvelope::new("a", "b", MessageType::Request, vec![42]);
    let cloned = env.clone();
    assert_eq!(env.from, cloned.from);
    assert_eq!(env.to, cloned.to);
    assert_eq!(env.data, cloned.data);
    assert_eq!(env.message_type, cloned.message_type);
}

#[test]
fn test_envelope_builder_new() {
    let builder = EnvelopeBuilder::new("from", "to");
    let env = builder.build();
    assert_eq!(env.from, "from");
    assert_eq!(env.to, "to");
    assert_eq!(env.message_type, MessageType::Data);
}

#[test]
fn test_envelope_builder_message_type() {
    let env = EnvelopeBuilder::new("a", "b")
        .message_type(MessageType::Request)
        .build();
    assert_eq!(env.message_type, MessageType::Request);
}

#[test]
fn test_envelope_builder_data() {
    let env = EnvelopeBuilder::new("a", "b")
        .data(vec![1, 2, 3, 4])
        .build();
    assert_eq!(env.data, vec![1, 2, 3, 4]);
}

#[test]
fn test_envelope_builder_data_from_slice() {
    let data = [10, 20, 30];
    let env = EnvelopeBuilder::new("a", "b")
        .data_from_slice(&data)
        .build();
    assert_eq!(env.data, vec![10, 20, 30]);
}

#[test]
fn test_envelope_builder_session_id() {
    let env = EnvelopeBuilder::new("a", "b")
        .session_id(12345)
        .build();
    assert_eq!(env.session_id, Some(12345));
}

#[test]
fn test_envelope_builder_security_level() {
    let env = EnvelopeBuilder::new("a", "b")
        .security_level(SecurityLevel::Encrypted)
        .build();
    assert_eq!(env.sec_level, SecurityLevel::Encrypted);
}

#[test]
fn test_envelope_builder_chained() {
    let env = EnvelopeBuilder::new("client", "server")
        .message_type(MessageType::Request)
        .data(vec![0x42])
        .session_id(999)
        .security_level(SecurityLevel::Signed)
        .build();

    assert_eq!(env.from, "client");
    assert_eq!(env.to, "server");
    assert_eq!(env.message_type, MessageType::Request);
    assert_eq!(env.data, vec![0x42]);
    assert_eq!(env.session_id, Some(999));
    assert_eq!(env.sec_level, SecurityLevel::Signed);
}

#[test]
fn test_envelope_builder_build_validated_success() {
    let result = EnvelopeBuilder::new("sender", "receiver")
        .data(vec![1, 2, 3])
        .build_validated();
    assert!(result.is_ok());
}

#[test]
fn test_envelope_builder_build_validated_empty_source() {
    let result = EnvelopeBuilder::new("", "receiver")
        .build_validated();
    assert!(matches!(result, Err(MessageError::EmptySource)));
}

#[test]
fn test_envelope_builder_build_validated_empty_dest() {
    let result = EnvelopeBuilder::new("sender", "")
        .build_validated();
    assert!(matches!(result, Err(MessageError::EmptyDestination)));
}

#[test]
fn test_ipc_message_with_timestamp() {
    let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
    assert_eq!(msg.from, "sender");
    assert_eq!(msg.to, "receiver");
    assert_eq!(msg.data, b"hello".to_vec());
    assert_eq!(msg.timestamp_ms, 1000);
}

#[test]
fn test_ipc_message_validate_integrity() {
    let msg = IpcMessage::with_timestamp("a", "b", b"test data", 12345);
    assert!(msg.validate_integrity());
}

#[test]
fn test_ipc_message_payload_size() {
    let msg = IpcMessage::with_timestamp("a", "b", b"hello", 0);
    assert_eq!(msg.payload_size(), 5);
}

#[test]
fn test_ipc_message_is_empty() {
    let msg = IpcMessage::with_timestamp("a", "b", b"", 0);
    assert!(msg.is_empty());

    let msg2 = IpcMessage::with_timestamp("a", "b", b"x", 0);
    assert!(!msg2.is_empty());
}

#[test]
fn test_ipc_message_display() {
    let msg = IpcMessage::with_timestamp("sender", "receiver", b"hello", 1000);
    let display = alloc::format!("{}", msg);
    assert!(display.contains("sender"));
    assert!(display.contains("receiver"));
    assert!(display.contains("5 bytes"));
}

#[test]
fn test_ipc_message_clone() {
    let msg = IpcMessage::with_timestamp("a", "b", b"data", 500);
    let cloned = msg.clone();
    assert_eq!(msg.from, cloned.from);
    assert_eq!(msg.to, cloned.to);
    assert_eq!(msg.data, cloned.data);
    assert_eq!(msg.timestamp_ms, cloned.timestamp_ms);
}

#[test]
fn test_max_payload_size_constant() {
    assert_eq!(MAX_PAYLOAD_SIZE, 16 * 1024 * 1024);
}

#[test]
fn test_max_message_size_constant() {
    assert_eq!(MAX_MESSAGE_SIZE, 1024 * 1024);
}

#[test]
fn test_security_level_all_variants_have_str() {
    let levels = [
        SecurityLevel::None,
        SecurityLevel::Signed,
        SecurityLevel::Encrypted,
    ];
    for level in levels {
        assert!(!level.as_str().is_empty());
    }
}

#[test]
fn test_message_type_all_variants_have_str() {
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
        assert!(!mt.as_str().is_empty());
    }
}

#[test]
fn test_message_error_all_variants_have_str() {
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
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_envelope_with_various_data_sizes() {
    let empty = IpcEnvelope::new("a", "b", MessageType::Data, vec![]);
    assert!(empty.is_empty());
    assert!(empty.is_valid());

    let small = IpcEnvelope::new("a", "b", MessageType::Data, vec![1; 10]);
    assert_eq!(small.len(), 10);
    assert!(small.is_valid());

    let medium = IpcEnvelope::new("a", "b", MessageType::Data, vec![2; 1000]);
    assert_eq!(medium.len(), 1000);
    assert!(medium.is_valid());
}

#[test]
fn test_envelope_response_preserves_session() {
    let mut req = IpcEnvelope::new("a", "b", MessageType::Request, vec![]);
    req.session_id = Some(0xDEADBEEF);

    let resp = req.create_response(vec![]);
    assert_eq!(resp.session_id, Some(0xDEADBEEF));
}

#[test]
fn test_envelope_error_response_preserves_session() {
    let mut req = IpcEnvelope::new("a", "b", MessageType::Request, vec![]);
    req.session_id = Some(0xCAFEBABE);

    let err_resp = req.create_error_response(vec![]);
    assert_eq!(err_resp.session_id, Some(0xCAFEBABE));
}

#[test]
fn test_message_integrity_different_data() {
    let msg1 = IpcMessage::with_timestamp("a", "b", b"data1", 1000);
    let msg2 = IpcMessage::with_timestamp("a", "b", b"data2", 1000);
    assert!(msg1.validate_integrity());
    assert!(msg2.validate_integrity());
}

#[test]
fn test_message_integrity_different_timestamps() {
    let msg1 = IpcMessage::with_timestamp("a", "b", b"data", 1000);
    let msg2 = IpcMessage::with_timestamp("a", "b", b"data", 2000);
    assert!(msg1.validate_integrity());
    assert!(msg2.validate_integrity());
}

#[test]
fn test_message_integrity_different_endpoints() {
    let msg1 = IpcMessage::with_timestamp("a", "b", b"data", 1000);
    let msg2 = IpcMessage::with_timestamp("x", "y", b"data", 1000);
    assert!(msg1.validate_integrity());
    assert!(msg2.validate_integrity());
}

