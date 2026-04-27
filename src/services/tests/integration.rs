use crate::services::client::ClientError;
use crate::services::protocol::{ServiceOp, MAX_PAYLOAD, MSG_VERSION};
use crate::services::registry::{RegError, MAX_SERVICES};
use crate::services::server::parsing::{encode_response, parse_request};
use crate::services::server::ServerError;
use crate::services::*;
use crate::test::framework::TestResult;
use alloc::vec::Vec;

pub(crate) fn test_request_encode_then_parse() -> TestResult {
    let original = ServiceRequest::new(42, ServiceOp::Write, alloc::vec![1, 2, 3, 4]);
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.seq != original.seq {
        return TestResult::Fail;
    }
    if req.op != original.op {
        return TestResult::Fail;
    }
    if req.payload != original.payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_ping() -> TestResult {
    let original = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Ping {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_open() -> TestResult {
    let original = ServiceRequest::new(2, ServiceOp::Open, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Open {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_close() -> TestResult {
    let original = ServiceRequest::new(3, ServiceOp::Close, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Close {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_read() -> TestResult {
    let original = ServiceRequest::new(4, ServiceOp::Read, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Read {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_ioctl() -> TestResult {
    let original = ServiceRequest::new(6, ServiceOp::Ioctl, alloc::vec![0xFF]);
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Ioctl {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_query() -> TestResult {
    let original = ServiceRequest::new(7, ServiceOp::Query, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Query {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_subscribe() -> TestResult {
    let original = ServiceRequest::new(8, ServiceOp::Subscribe, alloc::vec![1, 2]);
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Subscribe {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_unsubscribe() -> TestResult {
    let original = ServiceRequest::new(9, ServiceOp::Unsubscribe, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    if parsed.is_none() {
        return TestResult::Fail;
    }
    let req = parsed.unwrap();
    if req.op != ServiceOp::Unsubscribe {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_preserves_seq() -> TestResult {
    for seq in [0u32, 1, 100, 1000, u32::MAX / 2, u32::MAX] {
        let original = ServiceRequest::new(seq, ServiceOp::Ping, Vec::new());
        let encoded = original.encode();
        let parsed = parse_request(&encoded).unwrap();
        if parsed.seq != seq {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_preserves_flags() -> TestResult {
    let mut original = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    original.flags = 0x1234;
    let encoded = original.encode();
    let parsed = parse_request(&encoded).unwrap();
    if parsed.flags != 0x1234 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_encode_parse_preserves_payload() -> TestResult {
    let payload: Vec<u8> = (0..100).map(|i| i as u8).collect();
    let original = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    let encoded = original.encode();
    let parsed = parse_request(&encoded).unwrap();
    if parsed.payload != payload {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_response_ok_then_encode() -> TestResult {
    let resp = ServiceResponse::ok(42, alloc::vec![5, 6, 7]);
    let encoded = encode_response(&resp);
    if encoded.len() != 8 + 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_response_err_then_encode() -> TestResult {
    let resp = ServiceResponse::err(99, -500);
    let encoded = encode_response(&resp);
    let status = i32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    if status != -500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_check_with_service_cap() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    if !cap.has(CAP_VFS) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_NET) {
        return TestResult::Fail;
    }
    if !cap.has(CAP_VFS | CAP_NET) {
        return TestResult::Fail;
    }
    if cap.has(CAP_CRYPTO) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_expiry_logic() -> TestResult {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 1000);
    if cap.is_expired(500) {
        return TestResult::Fail;
    }
    if cap.is_expired(1000) {
        return TestResult::Fail;
    }
    if !cap.is_expired(1001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_message_roundtrip_request() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Read, alloc::vec![1, 2, 3]);
    let msg = ServiceMessage::Request(req.clone());
    match msg {
        ServiceMessage::Request(r) => {
            if r.seq != req.seq {
                return TestResult::Fail;
            }
            if r.op != req.op {
                return TestResult::Fail;
            }
            if r.payload != req.payload {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_service_message_roundtrip_response() -> TestResult {
    let resp = ServiceResponse::ok(1, alloc::vec![4, 5, 6]);
    let msg = ServiceMessage::Response(resp.clone());
    match msg {
        ServiceMessage::Response(r) => {
            if r.seq != resp.seq {
                return TestResult::Fail;
            }
            if r.status != resp.status {
                return TestResult::Fail;
            }
            if r.payload != resp.payload {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_all_ops_can_be_encoded_and_parsed() -> TestResult {
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
        let req = ServiceRequest::new(i as u32, *op, Vec::new());
        let encoded = req.encode();
        let parsed = parse_request(&encoded);
        if parsed.is_none() {
            return TestResult::Fail;
        }
        if parsed.unwrap().op != *op {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_client_error_from_response_status() -> TestResult {
    let resp = ServiceResponse::err(1, -403);
    let err = ClientError::RemoteError(resp.status);
    match err {
        ClientError::RemoteError(code) => {
            if code != -403 {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_cap_bits_do_not_overlap() -> TestResult {
    let all_caps = [
        CAP_VFS,
        CAP_NET,
        CAP_DISPLAY,
        CAP_DRIVER,
        CAP_CRYPTO,
        CAP_INPUT,
        CAP_AUDIO,
        CAP_ZK,
        CAP_GPU,
        CAP_APPS,
        CAP_AGENTS,
        CAP_SHELL,
        CAP_ADMIN,
    ];
    for i in 0..all_caps.len() {
        for j in (i + 1)..all_caps.len() {
            if all_caps[i] & all_caps[j] != 0 {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_combined_check() -> TestResult {
    let required = CAP_VFS | CAP_NET | CAP_CRYPTO;
    let cap = ServiceCap::new(required, 1);
    if !cap.has(required) {
        return TestResult::Fail;
    }

    let partial = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    if partial.has(required) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_error_types_are_distinct() -> TestResult {
    let cap_err = CapError::NoCap;
    let _cap_err2 = CapError::InsufficientCaps;
    let client_err = ClientError::NotFound;
    let _client_err2 = ClientError::Timeout;
    let server_err = ServerError::RegistrationFailed;
    let _server_err2 = ServerError::BindFailed;
    let reg_err = RegError::Full;
    let _reg_err2 = RegError::Exists;

    let cap_debug = alloc::format!("{:?}", cap_err);
    let client_debug = alloc::format!("{:?}", client_err);
    let server_debug = alloc::format!("{:?}", server_err);
    let reg_debug = alloc::format!("{:?}", reg_err);

    if !cap_debug.contains("NoCap") {
        return TestResult::Fail;
    }
    if !client_debug.contains("NotFound") {
        return TestResult::Fail;
    }
    if !server_debug.contains("RegistrationFailed") {
        return TestResult::Fail;
    }
    if !reg_debug.contains("Full") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_request_with_max_payload_indicator() -> TestResult {
    let payload: Vec<u8> = (0..MAX_PAYLOAD).map(|i| (i % 256) as u8).collect();
    let req = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    if req.payload.len() != MAX_PAYLOAD {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_endpoint_with_all_fields() -> TestResult {
    use crate::services::registry::ServiceEndpoint;
    let ep = ServiceEndpoint {
        name: alloc::string::String::from("test_service"),
        port: 8080,
        pid: 42,
        caps_required: CAP_VFS | CAP_NET,
    };
    if ep.name != "test_service" {
        return TestResult::Fail;
    }
    if ep.port != 8080 {
        return TestResult::Fail;
    }
    if ep.pid != 42 {
        return TestResult::Fail;
    }
    if ep.caps_required != CAP_VFS | CAP_NET {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_version_compatibility() -> TestResult {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    if encoded[0] != MSG_VERSION {
        return TestResult::Fail;
    }
    if MSG_VERSION != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_response_status_codes() -> TestResult {
    let ok = ServiceResponse::ok(1, Vec::new());
    if ok.status != 0 {
        return TestResult::Fail;
    }

    let err_cap = ServiceResponse::err(2, -403);
    if err_cap.status != -403 {
        return TestResult::Fail;
    }

    let err_not_found = ServiceResponse::err(3, -404);
    if err_not_found.status != -404 {
        return TestResult::Fail;
    }

    let err_internal = ServiceResponse::err(4, -500);
    if err_internal.status != -500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_encode_decode_consistency() -> TestResult {
    let original_req = ServiceRequest::new(12345, ServiceOp::Query, alloc::vec![0xAA, 0xBB, 0xCC]);
    let encoded = original_req.encode();
    let decoded = parse_request(&encoded).unwrap();

    if decoded.seq != original_req.seq {
        return TestResult::Fail;
    }
    if decoded.op != original_req.op {
        return TestResult::Fail;
    }
    if decoded.payload != original_req.payload {
        return TestResult::Fail;
    }

    let original_resp = ServiceResponse::ok(54321, alloc::vec![0x11, 0x22, 0x33]);
    let resp_encoded = encode_response(&original_resp);

    let seq =
        u32::from_le_bytes([resp_encoded[0], resp_encoded[1], resp_encoded[2], resp_encoded[3]]);
    let status =
        i32::from_le_bytes([resp_encoded[4], resp_encoded[5], resp_encoded[6], resp_encoded[7]]);

    if seq != original_resp.seq {
        return TestResult::Fail;
    }
    if status != original_resp.status {
        return TestResult::Fail;
    }
    if &resp_encoded[8..] != &original_resp.payload[..] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_services_bounds() -> TestResult {
    if MAX_SERVICES == 0 {
        return TestResult::Fail;
    }
    if MAX_SERVICES > 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cap_admin_is_highest_bit() -> TestResult {
    if CAP_ADMIN != 1u64 << 63 {
        return TestResult::Fail;
    }
    if CAP_ADMIN <= CAP_VFS {
        return TestResult::Fail;
    }
    if CAP_ADMIN <= CAP_NET {
        return TestResult::Fail;
    }
    if CAP_ADMIN <= CAP_SHELL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_service_cap_no_expiry_means_never_expires() -> TestResult {
    let cap = ServiceCap::new(CAP_VFS, 1);
    if cap.expires_ms != 0 {
        return TestResult::Fail;
    }
    if cap.is_expired(0) {
        return TestResult::Fail;
    }
    if cap.is_expired(u64::MAX - 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
