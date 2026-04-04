use crate::services::client::ClientError;

#[test]
fn test_client_error_not_found_variant() {
    let err = ClientError::NotFound;
    assert_eq!(err, ClientError::NotFound);
}

#[test]
fn test_client_error_capability_denied_variant() {
    let err = ClientError::CapabilityDenied;
    assert_eq!(err, ClientError::CapabilityDenied);
}

#[test]
fn test_client_error_send_failed_variant() {
    let err = ClientError::SendFailed;
    assert_eq!(err, ClientError::SendFailed);
}

#[test]
fn test_client_error_recv_failed_variant() {
    let err = ClientError::RecvFailed;
    assert_eq!(err, ClientError::RecvFailed);
}

#[test]
fn test_client_error_timeout_variant() {
    let err = ClientError::Timeout;
    assert_eq!(err, ClientError::Timeout);
}

#[test]
fn test_client_error_remote_error_variant() {
    let err = ClientError::RemoteError(-1);
    match err {
        ClientError::RemoteError(code) => assert_eq!(code, -1),
        _ => panic!("Expected RemoteError variant"),
    }
}

#[test]
fn test_client_error_remote_error_various_codes() {
    let err1 = ClientError::RemoteError(-403);
    let err2 = ClientError::RemoteError(-404);
    let err3 = ClientError::RemoteError(-500);
    match err1 { ClientError::RemoteError(c) => assert_eq!(c, -403), _ => panic!() }
    match err2 { ClientError::RemoteError(c) => assert_eq!(c, -404), _ => panic!() }
    match err3 { ClientError::RemoteError(c) => assert_eq!(c, -500), _ => panic!() }
}

#[test]
fn test_client_error_equality_simple() {
    assert_eq!(ClientError::NotFound, ClientError::NotFound);
    assert_eq!(ClientError::CapabilityDenied, ClientError::CapabilityDenied);
    assert_eq!(ClientError::SendFailed, ClientError::SendFailed);
    assert_eq!(ClientError::RecvFailed, ClientError::RecvFailed);
    assert_eq!(ClientError::Timeout, ClientError::Timeout);
}

#[test]
fn test_client_error_equality_remote_error() {
    assert_eq!(ClientError::RemoteError(-1), ClientError::RemoteError(-1));
    assert_ne!(ClientError::RemoteError(-1), ClientError::RemoteError(-2));
}

#[test]
fn test_client_error_inequality() {
    assert_ne!(ClientError::NotFound, ClientError::Timeout);
    assert_ne!(ClientError::CapabilityDenied, ClientError::SendFailed);
    assert_ne!(ClientError::RecvFailed, ClientError::RemoteError(0));
}

#[test]
fn test_client_error_clone() {
    let err = ClientError::Timeout;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_client_error_clone_remote_error() {
    let err = ClientError::RemoteError(-42);
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_client_error_copy() {
    let err = ClientError::SendFailed;
    let copied: ClientError = err;
    assert_eq!(err, copied);
}

#[test]
fn test_client_error_copy_remote_error() {
    let err = ClientError::RemoteError(-100);
    let copied: ClientError = err;
    assert_eq!(err, copied);
}

#[test]
fn test_client_error_debug_not_found() {
    let err = ClientError::NotFound;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("NotFound"));
}

#[test]
fn test_client_error_debug_capability_denied() {
    let err = ClientError::CapabilityDenied;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("CapabilityDenied"));
}

#[test]
fn test_client_error_debug_send_failed() {
    let err = ClientError::SendFailed;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("SendFailed"));
}

#[test]
fn test_client_error_debug_recv_failed() {
    let err = ClientError::RecvFailed;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("RecvFailed"));
}

#[test]
fn test_client_error_debug_timeout() {
    let err = ClientError::Timeout;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("Timeout"));
}

#[test]
fn test_client_error_debug_remote_error() {
    let err = ClientError::RemoteError(-999);
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("RemoteError"));
    assert!(debug_str.contains("-999"));
}

#[test]
fn test_client_error_remote_error_zero() {
    let err = ClientError::RemoteError(0);
    match err {
        ClientError::RemoteError(code) => assert_eq!(code, 0),
        _ => panic!("Expected RemoteError"),
    }
}

#[test]
fn test_client_error_remote_error_positive() {
    let err = ClientError::RemoteError(200);
    match err {
        ClientError::RemoteError(code) => assert_eq!(code, 200),
        _ => panic!("Expected RemoteError"),
    }
}

#[test]
fn test_client_error_remote_error_min() {
    let err = ClientError::RemoteError(i32::MIN);
    match err {
        ClientError::RemoteError(code) => assert_eq!(code, i32::MIN),
        _ => panic!("Expected RemoteError"),
    }
}

#[test]
fn test_client_error_remote_error_max() {
    let err = ClientError::RemoteError(i32::MAX);
    match err {
        ClientError::RemoteError(code) => assert_eq!(code, i32::MAX),
        _ => panic!("Expected RemoteError"),
    }
}

#[test]
fn test_client_error_all_variants_distinct() {
    let variants: [ClientError; 6] = [
        ClientError::NotFound,
        ClientError::CapabilityDenied,
        ClientError::SendFailed,
        ClientError::RecvFailed,
        ClientError::Timeout,
        ClientError::RemoteError(0),
    ];
    for i in 0..variants.len() {
        for j in (i + 1)..variants.len() {
            assert_ne!(variants[i], variants[j]);
        }
    }
}

#[test]
fn test_service_client_connect_nonexistent() {
    let result = crate::services::ServiceClient::connect("nonexistent_service_abc123");
    assert!(result.is_err());
}

#[test]
fn test_service_client_connect_empty_name() {
    let result = crate::services::ServiceClient::connect("");
    assert!(result.is_err());
}

#[test]
fn test_service_client_connect_returns_not_found_for_unknown() {
    let result = crate::services::ServiceClient::connect("unknown_xyz_789");
    match result {
        Err(ClientError::NotFound) => {}
        Err(e) => panic!("Expected NotFound, got {:?}", e),
        Ok(_) => panic!("Expected error"),
    }
}
