use crate::network::socks::{SocksError, error_message};

#[test]
fn test_socks_error_connection_failed() {
    let err = SocksError::ConnectionFailed;
    assert_eq!(err, SocksError::ConnectionFailed);
}

#[test]
fn test_socks_error_auth_failed() {
    let err = SocksError::AuthFailed;
    assert_eq!(err, SocksError::AuthFailed);
}

#[test]
fn test_socks_error_target_unreachable() {
    let err = SocksError::TargetUnreachable;
    assert_eq!(err, SocksError::TargetUnreachable);
}

#[test]
fn test_socks_error_timeout() {
    let err = SocksError::Timeout;
    assert_eq!(err, SocksError::Timeout);
}

#[test]
fn test_socks_error_protocol_error() {
    let err = SocksError::ProtocolError;
    assert_eq!(err, SocksError::ProtocolError);
}

#[test]
fn test_socks_error_send_failed() {
    let err = SocksError::SendFailed;
    assert_eq!(err, SocksError::SendFailed);
}

#[test]
fn test_socks_error_recv_failed() {
    let err = SocksError::RecvFailed;
    assert_eq!(err, SocksError::RecvFailed);
}

#[test]
fn test_socks_error_equality() {
    assert_eq!(SocksError::Timeout, SocksError::Timeout);
    assert_ne!(SocksError::Timeout, SocksError::SendFailed);
}

#[test]
fn test_socks_error_clone() {
    let err = SocksError::AuthFailed;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_socks_error_copy() {
    let err = SocksError::ProtocolError;
    let copied: SocksError = err;
    assert_eq!(err, copied);
}

#[test]
fn test_error_message_connection_failed() {
    let msg = error_message(SocksError::ConnectionFailed);
    assert_eq!(msg, "Connection failed");
}

#[test]
fn test_error_message_auth_failed() {
    let msg = error_message(SocksError::AuthFailed);
    assert_eq!(msg, "Authentication failed");
}

#[test]
fn test_error_message_target_unreachable() {
    let msg = error_message(SocksError::TargetUnreachable);
    assert_eq!(msg, "Target unreachable");
}

#[test]
fn test_error_message_timeout() {
    let msg = error_message(SocksError::Timeout);
    assert_eq!(msg, "Connection timed out");
}

#[test]
fn test_error_message_protocol_error() {
    let msg = error_message(SocksError::ProtocolError);
    assert_eq!(msg, "Protocol error");
}

#[test]
fn test_error_message_send_failed() {
    let msg = error_message(SocksError::SendFailed);
    assert_eq!(msg, "Send failed");
}

#[test]
fn test_error_message_recv_failed() {
    let msg = error_message(SocksError::RecvFailed);
    assert_eq!(msg, "Receive failed");
}

#[test]
fn test_all_error_variants_distinct() {
    let errors = [
        SocksError::ConnectionFailed,
        SocksError::AuthFailed,
        SocksError::TargetUnreachable,
        SocksError::Timeout,
        SocksError::ProtocolError,
        SocksError::SendFailed,
        SocksError::RecvFailed,
    ];
    for i in 0..errors.len() {
        for j in (i + 1)..errors.len() {
            assert_ne!(errors[i], errors[j]);
        }
    }
}

#[test]
fn test_all_error_messages_non_empty() {
    let errors = [
        SocksError::ConnectionFailed,
        SocksError::AuthFailed,
        SocksError::TargetUnreachable,
        SocksError::Timeout,
        SocksError::ProtocolError,
        SocksError::SendFailed,
        SocksError::RecvFailed,
    ];
    for err in &errors {
        let msg = error_message(*err);
        assert!(!msg.is_empty());
    }
}
