use crate::services::protocol::{ServiceOp, MAX_PAYLOAD, MSG_VERSION};
use crate::services::*;
use crate::test::framework::TestResult;
use alloc::vec::Vec;

pub(crate) fn test_msg_version_is_one() -> TestResult {
    if MSG_VERSION != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_payload_is_4096() -> TestResult {
    if MAX_PAYLOAD != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_ping_value() -> TestResult {
    if ServiceOp::Ping as u16 != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_open_value() -> TestResult {
    if ServiceOp::Open as u16 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_close_value() -> TestResult {
    if ServiceOp::Close as u16 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_read_value() -> TestResult {
    if ServiceOp::Read as u16 != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_write_value() -> TestResult {
    if ServiceOp::Write as u16 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_ioctl_value() -> TestResult {
    if ServiceOp::Ioctl as u16 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_query_value() -> TestResult {
    if ServiceOp::Query as u16 != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_subscribe_value() -> TestResult {
    if ServiceOp::Subscribe as u16 != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_unsubscribe_value() -> TestResult {
    if ServiceOp::Unsubscribe as u16 != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_values_are_sequential() -> TestResult {
    let ops = [
        ServiceOp::Ping,
        ServiceOp::Open,
        ServiceOp::Close,
        ServiceOp::Read,
        ServiceOp::Write,
        ServiceOp::Ioctl,
        ServiceOp::Query,
        ServiceOp::Subscribe,
        ServiceOp::Unsubscribe,
    ];
    for (i, op) in ops.iter().enumerate() {
        if *op as u16 != i as u16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_clone() -> TestResult {
    let op = ServiceOp::Read;
    let cloned = op.clone();
    if op != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_copy() -> TestResult {
    let op = ServiceOp::Write;
    let copied: ServiceOp = op;
    if op != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_equality() -> TestResult {
    if ServiceOp::Ping != ServiceOp::Ping {
        return TestResult::Fail;
    }
    if ServiceOp::Ping == ServiceOp::Open {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_op_debug_format() -> TestResult {
    let op = ServiceOp::Query;
    let debug_str = alloc::format!("{:?}", op);
    if !debug_str.contains("Query") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_new_empty_payload() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    if req.seq != 1 {
        return TestResult::Fail;
    }
    if req.op != ServiceOp::Ping {
        return TestResult::Fail;
    }
    if req.flags != 0 {
        return TestResult::Fail;
    }
    if !req.payload.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_new_with_payload() -> TestResult {
    let payload = alloc::vec![1, 2, 3, 4, 5];
    let req = ServiceRequest::new(42, ServiceOp::Write, payload.clone());
    if req.seq != 42 {
        return TestResult::Fail;
    }
    if req.op != ServiceOp::Write {
        return TestResult::Fail;
    }
    if req.payload != payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_minimum_length() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    if encoded.len() < 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_version_byte() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    if encoded[0] != MSG_VERSION {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_reserved_byte() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    if encoded[1] != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_seq_bytes() -> TestResult {
    let req = ServiceRequest::new(0x12345678, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    let seq = u32::from_le_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]);
    if seq != 0x12345678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_op_bytes() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Write, Vec::new());
    let encoded = req.encode();
    let op = u16::from_le_bytes([encoded[6], encoded[7]]);
    if op != ServiceOp::Write as u16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_flags_bytes() -> TestResult {
    let mut req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    req.flags = 0xABCD;
    let encoded = req.encode();
    let flags = u16::from_le_bytes([encoded[8], encoded[9]]);
    if flags != 0xABCD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_payload_length() -> TestResult {
    let payload = alloc::vec![1, 2, 3, 4, 5];
    let req = ServiceRequest::new(1, ServiceOp::Read, payload.clone());
    let encoded = req.encode();
    let len = u16::from_le_bytes([encoded[10], encoded[11]]);
    if len as usize != payload.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_payload_content() -> TestResult {
    let payload = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
    let req = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    let encoded = req.encode();
    if &encoded[12..] != &payload[..] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_encode_total_length() -> TestResult {
    let payload = alloc::vec![1, 2, 3, 4, 5, 6, 7, 8];
    let req = ServiceRequest::new(1, ServiceOp::Read, payload.clone());
    let encoded = req.encode();
    if encoded.len() != 12 + payload.len() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_clone() -> TestResult {
    let req = ServiceRequest::new(100, ServiceOp::Query, alloc::vec![1, 2, 3]);
    let cloned = req.clone();
    if req.seq != cloned.seq {
        return TestResult::Fail;
    }
    if req.op != cloned.op {
        return TestResult::Fail;
    }
    if req.flags != cloned.flags {
        return TestResult::Fail;
    }
    if req.payload != cloned.payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_debug_format() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let debug_str = alloc::format!("{:?}", req);
    if !debug_str.contains("ServiceRequest") {
        return TestResult::Fail;
    }
    if !debug_str.contains("seq") {
        return TestResult::Fail;
    }
    if !debug_str.contains("Ping") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_ok_empty_payload() -> TestResult {
    let resp = ServiceResponse::ok(1, Vec::new());
    if resp.seq != 1 {
        return TestResult::Fail;
    }
    if resp.status != 0 {
        return TestResult::Fail;
    }
    if !resp.payload.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_ok_with_payload() -> TestResult {
    let payload = alloc::vec![10, 20, 30];
    let resp = ServiceResponse::ok(42, payload.clone());
    if resp.seq != 42 {
        return TestResult::Fail;
    }
    if resp.status != 0 {
        return TestResult::Fail;
    }
    if resp.payload != payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_err_negative_status() -> TestResult {
    let resp = ServiceResponse::err(5, -1);
    if resp.seq != 5 {
        return TestResult::Fail;
    }
    if resp.status != -1 {
        return TestResult::Fail;
    }
    if !resp.payload.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_err_various_codes() -> TestResult {
    let resp1 = ServiceResponse::err(1, -403);
    let resp2 = ServiceResponse::err(2, -404);
    let resp3 = ServiceResponse::err(3, -500);
    if resp1.status != -403 {
        return TestResult::Fail;
    }
    if resp2.status != -404 {
        return TestResult::Fail;
    }
    if resp3.status != -500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_clone() -> TestResult {
    let resp = ServiceResponse::ok(99, alloc::vec![5, 6, 7]);
    let cloned = resp.clone();
    if resp.seq != cloned.seq {
        return TestResult::Fail;
    }
    if resp.status != cloned.status {
        return TestResult::Fail;
    }
    if resp.payload != cloned.payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_debug_format() -> TestResult {
    let resp = ServiceResponse::err(1, -1);
    let debug_str = alloc::format!("{:?}", resp);
    if !debug_str.contains("ServiceResponse") {
        return TestResult::Fail;
    }
    if !debug_str.contains("seq") {
        return TestResult::Fail;
    }
    if !debug_str.contains("status") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_message_request_variant() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let msg = ServiceMessage::Request(req);
    match msg {
        ServiceMessage::Request(r) => {
            if r.seq != 1 {
                return TestResult::Fail;
            }
        }
        ServiceMessage::Response(_) => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_service_message_response_variant() -> TestResult {
    let resp = ServiceResponse::ok(2, Vec::new());
    let msg = ServiceMessage::Response(resp);
    match msg {
        ServiceMessage::Request(_) => return TestResult::Fail,
        ServiceMessage::Response(r) => {
            if r.seq != 2 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_message_clone() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Open, Vec::new());
    let msg = ServiceMessage::Request(req);
    let cloned = msg.clone();
    match (msg, cloned) {
        (ServiceMessage::Request(m1), ServiceMessage::Request(m2)) => {
            if m1.seq != m2.seq {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_service_message_debug_format() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Close, Vec::new());
    let msg = ServiceMessage::Request(req);
    let debug_str = alloc::format!("{:?}", msg);
    if !debug_str.contains("Request") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_large_payload() -> TestResult {
    let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let req = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    let encoded = req.encode();
    if &encoded[12..] != &payload[..] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_seq_zero() -> TestResult {
    let req = ServiceRequest::new(0, ServiceOp::Ping, Vec::new());
    if req.seq != 0 {
        return TestResult::Fail;
    }
    let encoded = req.encode();
    let seq = u32::from_le_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]);
    if seq != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_request_seq_max() -> TestResult {
    let req = ServiceRequest::new(u32::MAX, ServiceOp::Ping, Vec::new());
    if req.seq != u32::MAX {
        return TestResult::Fail;
    }
    let encoded = req.encode();
    let seq = u32::from_le_bytes([encoded[2], encoded[3], encoded[4], encoded[5]]);
    if seq != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_positive_status() -> TestResult {
    let resp = ServiceResponse { seq: 1, status: 100, payload: Vec::new() };
    if resp.status != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_status_max_negative() -> TestResult {
    let resp = ServiceResponse::err(1, i32::MIN);
    if resp.status != i32::MIN {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_service_ops_are_distinct() -> TestResult {
    let ops = [
        ServiceOp::Ping,
        ServiceOp::Open,
        ServiceOp::Close,
        ServiceOp::Read,
        ServiceOp::Write,
        ServiceOp::Ioctl,
        ServiceOp::Query,
        ServiceOp::Subscribe,
        ServiceOp::Unsubscribe,
    ];
    for i in 0..ops.len() {
        for j in (i + 1)..ops.len() {
            if ops[i] == ops[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}
