use crate::services::*;
use crate::services::protocol::{ServiceOp, MSG_VERSION, MAX_PAYLOAD};
use crate::services::registry::{RegError, MAX_SERVICES};
use crate::services::client::ClientError;
use crate::services::server::ServerError;
use crate::services::server::parsing::{parse_request, encode_response};
use alloc::vec::Vec;

#[test]
fn test_request_encode_then_parse() {
    let original = ServiceRequest::new(42, ServiceOp::Write, alloc::vec![1, 2, 3, 4]);
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.seq, original.seq);
    assert_eq!(req.op, original.op);
    assert_eq!(req.payload, original.payload);
}

#[test]
fn test_request_encode_parse_ping() {
    let original = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Ping);
}

#[test]
fn test_request_encode_parse_open() {
    let original = ServiceRequest::new(2, ServiceOp::Open, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Open);
}

#[test]
fn test_request_encode_parse_close() {
    let original = ServiceRequest::new(3, ServiceOp::Close, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Close);
}

#[test]
fn test_request_encode_parse_read() {
    let original = ServiceRequest::new(4, ServiceOp::Read, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Read);
}

#[test]
fn test_request_encode_parse_ioctl() {
    let original = ServiceRequest::new(6, ServiceOp::Ioctl, alloc::vec![0xFF]);
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Ioctl);
}

#[test]
fn test_request_encode_parse_query() {
    let original = ServiceRequest::new(7, ServiceOp::Query, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Query);
}

#[test]
fn test_request_encode_parse_subscribe() {
    let original = ServiceRequest::new(8, ServiceOp::Subscribe, alloc::vec![1, 2]);
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Subscribe);
}

#[test]
fn test_request_encode_parse_unsubscribe() {
    let original = ServiceRequest::new(9, ServiceOp::Unsubscribe, Vec::new());
    let encoded = original.encode();
    let parsed = parse_request(&encoded);
    assert!(parsed.is_some());
    let req = parsed.unwrap();
    assert_eq!(req.op, ServiceOp::Unsubscribe);
}

#[test]
fn test_request_encode_parse_preserves_seq() {
    for seq in [0u32, 1, 100, 1000, u32::MAX / 2, u32::MAX] {
        let original = ServiceRequest::new(seq, ServiceOp::Ping, Vec::new());
        let encoded = original.encode();
        let parsed = parse_request(&encoded).unwrap();
        assert_eq!(parsed.seq, seq);
    }
}

#[test]
fn test_request_encode_parse_preserves_flags() {
    let mut original = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    original.flags = 0x1234;
    let encoded = original.encode();
    let parsed = parse_request(&encoded).unwrap();
    assert_eq!(parsed.flags, 0x1234);
}

#[test]
fn test_request_encode_parse_preserves_payload() {
    let payload: Vec<u8> = (0..100).map(|i| i as u8).collect();
    let original = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    let encoded = original.encode();
    let parsed = parse_request(&encoded).unwrap();
    assert_eq!(parsed.payload, payload);
}

#[test]
fn test_response_ok_then_encode() {
    let resp = ServiceResponse::ok(42, alloc::vec![5, 6, 7]);
    let encoded = encode_response(&resp);
    assert_eq!(encoded.len(), 8 + 3);
}

#[test]
fn test_response_err_then_encode() {
    let resp = ServiceResponse::err(99, -500);
    let encoded = encode_response(&resp);
    let status = i32::from_le_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    assert_eq!(status, -500);
}

#[test]
fn test_cap_check_with_service_cap() {
    let cap = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    assert!(cap.has(CAP_VFS));
    assert!(cap.has(CAP_NET));
    assert!(cap.has(CAP_VFS | CAP_NET));
    assert!(!cap.has(CAP_CRYPTO));
}

#[test]
fn test_cap_expiry_logic() {
    let cap = ServiceCap::with_expiry(CAP_VFS, 1, 1000);
    assert!(!cap.is_expired(500));
    assert!(!cap.is_expired(1000));
    assert!(cap.is_expired(1001));
}

#[test]
fn test_service_message_roundtrip_request() {
    let req = ServiceRequest::new(1, ServiceOp::Read, alloc::vec![1, 2, 3]);
    let msg = ServiceMessage::Request(req.clone());
    match msg {
        ServiceMessage::Request(r) => {
            assert_eq!(r.seq, req.seq);
            assert_eq!(r.op, req.op);
            assert_eq!(r.payload, req.payload);
        }
        _ => panic!("Expected Request"),
    }
}

#[test]
fn test_service_message_roundtrip_response() {
    let resp = ServiceResponse::ok(1, alloc::vec![4, 5, 6]);
    let msg = ServiceMessage::Response(resp.clone());
    match msg {
        ServiceMessage::Response(r) => {
            assert_eq!(r.seq, resp.seq);
            assert_eq!(r.status, resp.status);
            assert_eq!(r.payload, resp.payload);
        }
        _ => panic!("Expected Response"),
    }
}

#[test]
fn test_all_ops_can_be_encoded_and_parsed() {
    let ops = [
        ServiceOp::Ping, ServiceOp::Open, ServiceOp::Close,
        ServiceOp::Read, ServiceOp::Write, ServiceOp::Ioctl,
        ServiceOp::Query, ServiceOp::Subscribe, ServiceOp::Unsubscribe,
    ];
    for (i, op) in ops.iter().enumerate() {
        let req = ServiceRequest::new(i as u32, *op, Vec::new());
        let encoded = req.encode();
        let parsed = parse_request(&encoded);
        assert!(parsed.is_some(), "Failed to parse op {:?}", op);
        assert_eq!(parsed.unwrap().op, *op);
    }
}

#[test]
fn test_client_error_from_response_status() {
    let resp = ServiceResponse::err(1, -403);
    let err = ClientError::RemoteError(resp.status);
    match err {
        ClientError::RemoteError(code) => assert_eq!(code, -403),
        _ => panic!("Expected RemoteError"),
    }
}

#[test]
fn test_cap_bits_do_not_overlap() {
    let all_caps = [
        CAP_VFS, CAP_NET, CAP_DISPLAY, CAP_DRIVER, CAP_CRYPTO,
        CAP_INPUT, CAP_AUDIO, CAP_ZK, CAP_GPU, CAP_APPS,
        CAP_AGENTS, CAP_SHELL, CAP_ADMIN,
    ];
    for i in 0..all_caps.len() {
        for j in (i + 1)..all_caps.len() {
            assert_eq!(all_caps[i] & all_caps[j], 0);
        }
    }
}

#[test]
fn test_service_cap_combined_check() {
    let required = CAP_VFS | CAP_NET | CAP_CRYPTO;
    let cap = ServiceCap::new(required, 1);
    assert!(cap.has(required));

    let partial = ServiceCap::new(CAP_VFS | CAP_NET, 1);
    assert!(!partial.has(required));
}

#[test]
fn test_error_types_are_distinct() {
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

    assert!(cap_debug.contains("NoCap"));
    assert!(client_debug.contains("NotFound"));
    assert!(server_debug.contains("RegistrationFailed"));
    assert!(reg_debug.contains("Full"));
}

#[test]
fn test_request_with_max_payload_indicator() {
    let payload: Vec<u8> = (0..MAX_PAYLOAD).map(|i| (i % 256) as u8).collect();
    let req = ServiceRequest::new(1, ServiceOp::Write, payload.clone());
    assert_eq!(req.payload.len(), MAX_PAYLOAD);
}

#[test]
fn test_service_endpoint_with_all_fields() {
    use crate::services::registry::ServiceEndpoint;
    let ep = ServiceEndpoint {
        name: alloc::string::String::from("test_service"),
        port: 8080,
        pid: 42,
        caps_required: CAP_VFS | CAP_NET,
    };
    assert_eq!(ep.name, "test_service");
    assert_eq!(ep.port, 8080);
    assert_eq!(ep.pid, 42);
    assert_eq!(ep.caps_required, CAP_VFS | CAP_NET);
}

#[test]
fn test_version_compatibility() {
    let req = ServiceRequest::new(1, ServiceOp::Ping, Vec::new());
    let encoded = req.encode();
    assert_eq!(encoded[0], MSG_VERSION);
    assert_eq!(MSG_VERSION, 1);
}

#[test]
fn test_service_response_status_codes() {
    let ok = ServiceResponse::ok(1, Vec::new());
    assert_eq!(ok.status, 0);

    let err_cap = ServiceResponse::err(2, -403);
    assert_eq!(err_cap.status, -403);

    let err_not_found = ServiceResponse::err(3, -404);
    assert_eq!(err_not_found.status, -404);

    let err_internal = ServiceResponse::err(4, -500);
    assert_eq!(err_internal.status, -500);
}

#[test]
fn test_encode_decode_consistency() {
    let original_req = ServiceRequest::new(12345, ServiceOp::Query, alloc::vec![0xAA, 0xBB, 0xCC]);
    let encoded = original_req.encode();
    let decoded = parse_request(&encoded).unwrap();

    assert_eq!(decoded.seq, original_req.seq);
    assert_eq!(decoded.op, original_req.op);
    assert_eq!(decoded.payload, original_req.payload);

    let original_resp = ServiceResponse::ok(54321, alloc::vec![0x11, 0x22, 0x33]);
    let resp_encoded = encode_response(&original_resp);

    let seq = u32::from_le_bytes([resp_encoded[0], resp_encoded[1], resp_encoded[2], resp_encoded[3]]);
    let status = i32::from_le_bytes([resp_encoded[4], resp_encoded[5], resp_encoded[6], resp_encoded[7]]);

    assert_eq!(seq, original_resp.seq);
    assert_eq!(status, original_resp.status);
    assert_eq!(&resp_encoded[8..], &original_resp.payload[..]);
}

#[test]
fn test_max_services_bounds() {
    assert!(MAX_SERVICES > 0);
    assert!(MAX_SERVICES <= 1024);
}

#[test]
fn test_cap_admin_is_highest_bit() {
    assert_eq!(CAP_ADMIN, 1u64 << 63);
    assert!(CAP_ADMIN > CAP_VFS);
    assert!(CAP_ADMIN > CAP_NET);
    assert!(CAP_ADMIN > CAP_SHELL);
}

#[test]
fn test_service_cap_no_expiry_means_never_expires() {
    let cap = ServiceCap::new(CAP_VFS, 1);
    assert_eq!(cap.expires_ms, 0);
    assert!(!cap.is_expired(0));
    assert!(!cap.is_expired(u64::MAX - 1));
}
