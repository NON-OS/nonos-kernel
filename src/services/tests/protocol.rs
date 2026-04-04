use crate::services::*;
use crate::services::protocol::{ServiceOp, MSG_VERSION, MAX_PAYLOAD};
use alloc::vec::Vec;

#[test]
fn test_msg_version_is_one() {
    assert_eq!(MSG_VERSION, 1);
}

#[test]
fn test_max_payload_is_4096() {
    assert_eq!(MAX_PAYLOAD, 4096);
}

#[test]
fn test_service_op_ping_value() {
    assert_eq!(ServiceOp::Ping as u16, 0);
}

#[test]
fn test_service_op_open_value() {
    assert_eq!(ServiceOp::Open as u16, 1);
}

#[test]
fn test_service_op_close_value() {
    assert_eq!(ServiceOp::Close as u16, 2);
}

#[test]
fn test_service_op_read_value() {
    assert_eq!(ServiceOp::Read as u16, 3);
}

#[test]
fn test_service_op_write_value() {
    assert_eq!(ServiceOp::Write as u16, 4);
}

#[test]
fn test_service_op_ioctl_value() {
    assert_eq!(ServiceOp::Ioctl as u16, 5);
}

#[test]
fn test_service_op_query_value() {
    assert_eq!(ServiceOp::Query as u16, 6);
}

#[test]
fn test_service_op_subscribe_value() {
    assert_eq!(ServiceOp::Subscribe as u16, 7);
}

#[test]
fn test_service_op_unsubscribe_value() {
    assert_eq!(ServiceOp::Unsubscribe as u16, 8);
}

#[test]
fn test_service_op_values_are_sequential() {
    let ops = [
        ServiceOp::Ping, ServiceOp::Open, ServiceOp::Close,
        ServiceOp::Read, ServiceOp::Write, ServiceOp::Ioctl,
        ServiceOp::Query, ServiceOp::Subscribe, ServiceOp::Unsubscribe,
    ];
    for (i, op) in ops.iter().enumerate() {
        assert_eq!(*op as u16, i as u16);
    }
}

#[test]
fn test_service_op_clone() {
    let op = ServiceOp::Read;
    let cloned = op.clone();
    assert_eq!(op, cloned);
}

#[test]
fn test_service_op_copy() {
    let op = ServiceOp::Write;
    let copied: ServiceOp = op;
    assert_eq!(op, copied);
}

#[test]
fn test_service_op_equality() {
    assert_eq!(ServiceOp::Ping, ServiceOp::Ping);
    assert_ne!(ServiceOp::Ping, ServiceOp::Open);
}

#[test]
fn test_service_op_debug_format() {
    let op = ServiceOp::Query;
    let debug_str = alloc::format!("{:?}", op);
    assert!(debug_str.contains("Query"));
}

#[test]
fn test_service_request_new_empty_payload() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    assert_eq!(req.seq, 1);
    assert_eq!(req.op, ServiceOp::Ping);
    assert_eq!(req.flags, 0);
    assert!(req.payload.is_empty());
}

#[test]
fn test_service_request_new_with_payload() {
    let payload = alloc::vec![1, 2, 3, 4, 5];
    let req = ServiceRequest::new(42, ServiceOp::Write, payload.clone());
    assert_eq!(req.seq, 42);
    assert_eq!(req.op, ServiceOp::Write);
    assert_eq!(req.payload, payload);
}

#[test]
fn test_service_request_encode_minimum_length() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    assert!(encoded.len() >= 12);
}

#[test]
fn test_service_request_encode_version_byte() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    assert_eq!(encoded[0], MSG_VERSION);
}

#[test]
fn test_service_request_encode_reserved_byte() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    assert_eq!(encoded[1], 0);
}

#[test]
fn test_service_request_encode_seq_bytes() {
    let req = ServiceRequest::new(0x12345678, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    let seq = u32::from_le_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]);
    assert_eq!(seq, 0x12345678);
}

#[test]
fn test_service_request_encode_op_bytes() {
    let req = ServiceRequest::new(1, ServiceOp::Write, Vec::new());
    let encoded = req.encode();
    let op = u16::from_le_bytes([encoded[6], encoded[7]]);
    assert_eq!(op, ServiceOp::Write as u16);
}

#[test]
fn test_service_request_encode_flags_bytes() {
    let mut req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    req.flags = 0xABCD;
    let encoded = req.encode();
    let flags = u16::from_le_bytes([encoded[8], encoded[9]]);
    assert_eq!(flags, 0xABCD);
}

#[test]
fn test_service_request_encode_payload_length() {
    let payload = alloc::vec![1, 2, 3, 4, 5];
    let req = ServiceRequest::new(1, ServiceOp::Read, payload.clone());
    let encoded = req.encode();
    let len = u16::from_le_bytes([encoded[10], encoded[11]]);
    assert_eq!(len as usize, payload.len());
}

#[test]
fn test_service_request_encode_payload_content() {
    let payload = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
    let req = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    let encoded = req.encode();
    assert_eq!(&encoded[12..], &payload[..]);
}

#[test]
fn test_service_request_encode_total_length() {
    let payload = alloc::vec![1, 2, 3, 4, 5, 6, 7, 8];
    let req = ServiceRequest::new(1, ServiceOp::Read, payload.clone());
    let encoded = req.encode();
    assert_eq!(encoded.len(), 12 + payload.len());
}

#[test]
fn test_service_request_clone() {
    let req = ServiceRequest::new(100, ServiceOp::Query, alloc::vec![1, 2, 3]);
    let cloned = req.clone();
    assert_eq!(req.seq, cloned.seq);
    assert_eq!(req.op, cloned.op);
    assert_eq!(req.flags, cloned.flags);
    assert_eq!(req.payload, cloned.payload);
}

#[test]
fn test_service_request_debug_format() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let debug_str = alloc::format!("{:?}", req);
    assert!(debug_str.contains("ServiceRequest"));
    assert!(debug_str.contains("seq"));
    assert!(debug_str.contains("Ping"));
}

#[test]
fn test_service_response_ok_empty_payload() {
    let resp = ServiceResponse::ok(1, Vec::new());
    assert_eq!(resp.seq, 1);
    assert_eq!(resp.status, 0);
    assert!(resp.payload.is_empty());
}

#[test]
fn test_service_response_ok_with_payload() {
    let payload = alloc::vec![10, 20, 30];
    let resp = ServiceResponse::ok(42, payload.clone());
    assert_eq!(resp.seq, 42);
    assert_eq!(resp.status, 0);
    assert_eq!(resp.payload, payload);
}

#[test]
fn test_service_response_err_negative_status() {
    let resp = ServiceResponse::err(5, -1);
    assert_eq!(resp.seq, 5);
    assert_eq!(resp.status, -1);
    assert!(resp.payload.is_empty());
}

#[test]
fn test_service_response_err_various_codes() {
    let resp1 = ServiceResponse::err(1, -403);
    let resp2 = ServiceResponse::err(2, -404);
    let resp3 = ServiceResponse::err(3, -500);
    assert_eq!(resp1.status, -403);
    assert_eq!(resp2.status, -404);
    assert_eq!(resp3.status, -500);
}

#[test]
fn test_service_response_clone() {
    let resp = ServiceResponse::ok(99, alloc::vec![5, 6, 7]);
    let cloned = resp.clone();
    assert_eq!(resp.seq, cloned.seq);
    assert_eq!(resp.status, cloned.status);
    assert_eq!(resp.payload, cloned.payload);
}

#[test]
fn test_service_response_debug_format() {
    let resp = ServiceResponse::err(1, -1);
    let debug_str = alloc::format!("{:?}", resp);
    assert!(debug_str.contains("ServiceResponse"));
    assert!(debug_str.contains("seq"));
    assert!(debug_str.contains("status"));
}

#[test]
fn test_service_message_request_variant() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let msg = ServiceMessage::Request(req);
    match msg {
        ServiceMessage::Request(r) => assert_eq!(r.seq, 1),
        ServiceMessage::Response(_) => panic!("Expected Request variant"),
    }
}

#[test]
fn test_service_message_response_variant() {
    let resp = ServiceResponse::ok(2, Vec::new());
    let msg = ServiceMessage::Response(resp);
    match msg {
        ServiceMessage::Request(_) => panic!("Expected Response variant"),
        ServiceMessage::Response(r) => assert_eq!(r.seq, 2),
    }
}

#[test]
fn test_service_message_clone() {
    let req = ServiceRequest::new(1, ServiceOp::Open, Vec::new());
    let msg = ServiceMessage::Request(req);
    let cloned = msg.clone();
    match (msg, cloned) {
        (ServiceMessage::Request(m1), ServiceMessage::Request(m2)) => {
            assert_eq!(m1.seq, m2.seq);
        }
        _ => panic!("Clone should preserve variant"),
    }
}

#[test]
fn test_service_message_debug_format() {
    let req = ServiceRequest::new(1, ServiceOp::Close, Vec::new());
    let msg = ServiceMessage::Request(req);
    let debug_str = alloc::format!("{:?}", msg);
    assert!(debug_str.contains("Request"));
}

#[test]
fn test_service_request_large_payload() {
    let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let req = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    let encoded = req.encode();
    assert_eq!(&encoded[12..], &payload[..]);
}

#[test]
fn test_service_request_seq_zero() {
    let req = ServiceRequest::new(0, ServiceOp::Ping, Vec::new());
    assert_eq!(req.seq, 0);
    let encoded = req.encode();
    let seq = u32::from_le_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]);
    assert_eq!(seq, 0);
}

#[test]
fn test_service_request_seq_max() {
    let req = ServiceRequest::new(u32::MAX, ServiceOp::Ping, Vec::new());
    assert_eq!(req.seq, u32::MAX);
    let encoded = req.encode();
    let seq = u32::from_le_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]);
    assert_eq!(seq, u32::MAX);
}

#[test]
fn test_service_response_positive_status() {
    let resp = ServiceResponse { seq: 1, status: 100, payload: Vec::new() };
    assert_eq!(resp.status, 100);
}

#[test]
fn test_service_response_status_max_negative() {
    let resp = ServiceResponse::err(1, i32::MIN);
    assert_eq!(resp.status, i32::MIN);
}

#[test]
fn test_all_service_ops_are_distinct() {
    let ops = [
        ServiceOp::Ping, ServiceOp::Open, ServiceOp::Close,
        ServiceOp::Read, ServiceOp::Write, ServiceOp::Ioctl,
        ServiceOp::Query, ServiceOp::Subscribe, ServiceOp::Unsubscribe,
    ];
    for i in 0..ops.len() {
        for j in (i + 1)..ops.len() {
            assert_ne!(ops[i], ops[j]);
        }
    }
}
