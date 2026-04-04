// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::nym::types::constants::{
    NYM_PACKET_SIZE, NYM_PAYLOAD_SIZE, NYM_HEADER_SIZE, NYM_MAC_SIZE,
    NYM_ROUTING_INFO_SIZE, NYM_MIX_LAYERS, NYM_COVER_INTERVAL_MS,
    NYM_KEY_SIZE, NYM_NONCE_SIZE, NYM_TAG_SIZE, NYM_NODE_ADDRESS_SIZE,
    NYM_SURB_SIZE, NYM_FRAGMENT_SIZE, NYM_MAX_HOPS,
    NYM_DEFAULT_GATEWAY_PORT, NYM_DEFAULT_MIX_PORT,
    NYM_CONNECT_TIMEOUT_MS, NYM_READ_TIMEOUT_MS, NYM_WRITE_TIMEOUT_MS,
};
use crate::network::nym::types::ids::{MixNodeId, GatewayId, ClientId, SurbId};
use crate::network::nym::types::address::NymAddress;
use crate::network::nym::error::NymError;

#[test]
fn test_nym_packet_size() {
    assert_eq!(NYM_PACKET_SIZE, 2048);
}

#[test]
fn test_nym_payload_size() {
    assert_eq!(NYM_PAYLOAD_SIZE, 1024);
}

#[test]
fn test_nym_header_size() {
    assert_eq!(NYM_HEADER_SIZE, 816);
}

#[test]
fn test_nym_mac_size() {
    assert_eq!(NYM_MAC_SIZE, 16);
}

#[test]
fn test_nym_routing_info_size() {
    assert_eq!(NYM_ROUTING_INFO_SIZE, 32);
}

#[test]
fn test_nym_mix_layers() {
    assert_eq!(NYM_MIX_LAYERS, 5);
}

#[test]
fn test_nym_cover_interval_ms() {
    assert_eq!(NYM_COVER_INTERVAL_MS, 100);
}

#[test]
fn test_nym_key_size() {
    assert_eq!(NYM_KEY_SIZE, 32);
}

#[test]
fn test_nym_nonce_size() {
    assert_eq!(NYM_NONCE_SIZE, 12);
}

#[test]
fn test_nym_tag_size() {
    assert_eq!(NYM_TAG_SIZE, 16);
}

#[test]
fn test_nym_node_address_size() {
    assert_eq!(NYM_NODE_ADDRESS_SIZE, 32);
}

#[test]
fn test_nym_surb_size() {
    assert_eq!(NYM_SURB_SIZE, 296);
}

#[test]
fn test_nym_fragment_size() {
    assert_eq!(NYM_FRAGMENT_SIZE, 500);
}

#[test]
fn test_nym_max_hops() {
    assert_eq!(NYM_MAX_HOPS, 5);
}

#[test]
fn test_nym_default_gateway_port() {
    assert_eq!(NYM_DEFAULT_GATEWAY_PORT, 9000);
}

#[test]
fn test_nym_default_mix_port() {
    assert_eq!(NYM_DEFAULT_MIX_PORT, 1789);
}

#[test]
fn test_nym_connect_timeout_ms() {
    assert_eq!(NYM_CONNECT_TIMEOUT_MS, 15000);
}

#[test]
fn test_nym_read_timeout_ms() {
    assert_eq!(NYM_READ_TIMEOUT_MS, 5000);
}

#[test]
fn test_nym_write_timeout_ms() {
    assert_eq!(NYM_WRITE_TIMEOUT_MS, 10000);
}

#[test]
fn test_nym_packet_structure() {
    assert!(NYM_HEADER_SIZE + NYM_PAYLOAD_SIZE <= NYM_PACKET_SIZE);
}

#[test]
fn test_nym_max_hops_equals_mix_layers() {
    assert_eq!(NYM_MAX_HOPS, NYM_MIX_LAYERS);
}

#[test]
fn test_mixnode_id_from_bytes() {
    let bytes = [1u8; 32];
    let id = MixNodeId::from_bytes(&bytes);
    assert!(id.is_some());
    assert_eq!(id.unwrap().0, bytes);
}

#[test]
fn test_mixnode_id_from_bytes_wrong_size() {
    let bytes = [1u8; 16];
    let id = MixNodeId::from_bytes(&bytes);
    assert!(id.is_none());
}

#[test]
fn test_mixnode_id_as_bytes() {
    let bytes = [42u8; 32];
    let id = MixNodeId(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn test_mixnode_id_clone() {
    let id = MixNodeId([0xAB; 32]);
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

#[test]
fn test_mixnode_id_copy() {
    let id1 = MixNodeId([0xCD; 32]);
    let id2 = id1;
    assert_eq!(id1, id2);
}

#[test]
fn test_mixnode_id_equality() {
    let id1 = MixNodeId([1; 32]);
    let id2 = MixNodeId([1; 32]);
    let id3 = MixNodeId([2; 32]);
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

#[test]
fn test_mixnode_id_ordering() {
    let id1 = MixNodeId([1; 32]);
    let id2 = MixNodeId([2; 32]);
    assert!(id1 < id2);
}

#[test]
fn test_gateway_id_from_bytes() {
    let bytes = [0xFF; 32];
    let id = GatewayId::from_bytes(&bytes);
    assert!(id.is_some());
    assert_eq!(id.unwrap().0, bytes);
}

#[test]
fn test_gateway_id_from_bytes_wrong_size() {
    let bytes = [0xFF; 64];
    let id = GatewayId::from_bytes(&bytes);
    assert!(id.is_none());
}

#[test]
fn test_gateway_id_as_bytes() {
    let bytes = [0x11; 32];
    let id = GatewayId(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn test_gateway_id_clone() {
    let id = GatewayId([0x22; 32]);
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

#[test]
fn test_gateway_id_copy() {
    let id1 = GatewayId([0x33; 32]);
    let id2 = id1;
    assert_eq!(id1, id2);
}

#[test]
fn test_gateway_id_equality() {
    let id1 = GatewayId([5; 32]);
    let id2 = GatewayId([5; 32]);
    let id3 = GatewayId([6; 32]);
    assert_eq!(id1, id2);
    assert_ne!(id1, id3);
}

#[test]
fn test_client_id_from_bytes() {
    let bytes = [0xAA; 32];
    let id = ClientId::from_bytes(&bytes);
    assert!(id.is_some());
    assert_eq!(id.unwrap().0, bytes);
}

#[test]
fn test_client_id_from_bytes_wrong_size() {
    let bytes = [0xAA; 31];
    let id = ClientId::from_bytes(&bytes);
    assert!(id.is_none());
}

#[test]
fn test_client_id_as_bytes() {
    let bytes = [0xBB; 32];
    let id = ClientId(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn test_client_id_clone() {
    let id = ClientId([0xCC; 32]);
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

#[test]
fn test_client_id_copy() {
    let id1 = ClientId([0xDD; 32]);
    let id2 = id1;
    assert_eq!(id1, id2);
}

#[test]
fn test_surb_id_from_bytes() {
    let bytes = [0x12; 16];
    let id = SurbId::from_bytes(&bytes);
    assert!(id.is_some());
    assert_eq!(id.unwrap().0, bytes);
}

#[test]
fn test_surb_id_from_bytes_wrong_size() {
    let bytes = [0x12; 32];
    let id = SurbId::from_bytes(&bytes);
    assert!(id.is_none());
}

#[test]
fn test_surb_id_as_bytes() {
    let bytes = [0x34; 16];
    let id = SurbId(bytes);
    assert_eq!(id.as_bytes(), &bytes);
}

#[test]
fn test_surb_id_clone() {
    let id = SurbId([0x56; 16]);
    let cloned = id.clone();
    assert_eq!(id, cloned);
}

#[test]
fn test_surb_id_copy() {
    let id1 = SurbId([0x78; 16]);
    let id2 = id1;
    assert_eq!(id1, id2);
}

#[test]
fn test_nym_address_new() {
    let gateway = GatewayId([1; 32]);
    let client = ClientId([2; 32]);
    let addr = NymAddress::new(gateway, client);
    assert_eq!(addr.gateway, gateway);
    assert_eq!(addr.client_id, client);
}

#[test]
fn test_nym_address_to_bytes() {
    let gateway = GatewayId([0xAA; 32]);
    let client = ClientId([0xBB; 32]);
    let addr = NymAddress::new(gateway, client);
    let bytes = addr.to_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..32], &[0xAA; 32]);
    assert_eq!(&bytes[32..], &[0xBB; 32]);
}

#[test]
fn test_nym_address_from_bytes() {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&[0x11; 32]);
    bytes[32..].copy_from_slice(&[0x22; 32]);
    let addr = NymAddress::from_bytes(&bytes);
    assert!(addr.is_some());
    let addr = addr.unwrap();
    assert_eq!(addr.gateway.0, [0x11; 32]);
    assert_eq!(addr.client_id.0, [0x22; 32]);
}

#[test]
fn test_nym_address_from_bytes_wrong_size() {
    let bytes = [0u8; 32];
    let addr = NymAddress::from_bytes(&bytes);
    assert!(addr.is_none());
}

#[test]
fn test_nym_address_roundtrip() {
    let gateway = GatewayId([0x55; 32]);
    let client = ClientId([0x66; 32]);
    let original = NymAddress::new(gateway, client);
    let bytes = original.to_bytes();
    let restored = NymAddress::from_bytes(&bytes).unwrap();
    assert_eq!(original, restored);
}

#[test]
fn test_nym_address_clone() {
    let addr = NymAddress::new(GatewayId([1; 32]), ClientId([2; 32]));
    let cloned = addr.clone();
    assert_eq!(addr, cloned);
}

#[test]
fn test_nym_address_equality() {
    let addr1 = NymAddress::new(GatewayId([1; 32]), ClientId([2; 32]));
    let addr2 = NymAddress::new(GatewayId([1; 32]), ClientId([2; 32]));
    let addr3 = NymAddress::new(GatewayId([3; 32]), ClientId([2; 32]));
    assert_eq!(addr1, addr2);
    assert_ne!(addr1, addr3);
}

#[test]
fn test_nym_error_not_initialized() {
    let err = NymError::NotInitialized;
    assert_eq!(err.as_str(), "NYM client not initialized");
}

#[test]
fn test_nym_error_already_initialized() {
    let err = NymError::AlreadyInitialized;
    assert_eq!(err.as_str(), "NYM client already initialized");
}

#[test]
fn test_nym_error_connection_failed() {
    let err = NymError::ConnectionFailed;
    assert_eq!(err.as_str(), "Failed to connect to gateway");
}

#[test]
fn test_nym_error_not_connected() {
    let err = NymError::NotConnected;
    assert_eq!(err.as_str(), "Not connected to gateway");
}

#[test]
fn test_nym_error_handshake_failed() {
    let err = NymError::HandshakeFailed;
    assert_eq!(err.as_str(), "Gateway handshake failed");
}

#[test]
fn test_nym_error_send_failed() {
    let err = NymError::SendFailed;
    assert_eq!(err.as_str(), "Failed to send data");
}

#[test]
fn test_nym_error_receive_failed() {
    let err = NymError::ReceiveFailed;
    assert_eq!(err.as_str(), "Failed to receive data");
}

#[test]
fn test_nym_error_gateway_not_found() {
    let err = NymError::GatewayNotFound;
    assert_eq!(err.as_str(), "Gateway not found");
}

#[test]
fn test_nym_error_mixnode_not_found() {
    let err = NymError::MixNodeNotFound;
    assert_eq!(err.as_str(), "MixNode not found");
}

#[test]
fn test_nym_error_invalid_route() {
    let err = NymError::InvalidRoute;
    assert_eq!(err.as_str(), "Invalid route through mixnet");
}

#[test]
fn test_nym_error_invalid_packet() {
    let err = NymError::InvalidPacket;
    assert_eq!(err.as_str(), "Invalid Sphinx packet");
}

#[test]
fn test_nym_error_packet_too_large() {
    let err = NymError::PacketTooLarge;
    assert_eq!(err.as_str(), "Packet payload too large");
}

#[test]
fn test_nym_error_encryption_failed() {
    let err = NymError::EncryptionFailed;
    assert_eq!(err.as_str(), "Sphinx encryption failed");
}

#[test]
fn test_nym_error_decryption_failed() {
    let err = NymError::DecryptionFailed;
    assert_eq!(err.as_str(), "Sphinx decryption failed");
}

#[test]
fn test_nym_error_invalid_mac() {
    let err = NymError::InvalidMac;
    assert_eq!(err.as_str(), "Invalid MAC on packet");
}

#[test]
fn test_nym_error_invalid_header() {
    let err = NymError::InvalidHeader;
    assert_eq!(err.as_str(), "Invalid Sphinx header");
}

#[test]
fn test_nym_error_invalid_payload() {
    let err = NymError::InvalidPayload;
    assert_eq!(err.as_str(), "Invalid packet payload");
}

#[test]
fn test_nym_error_invalid_surb() {
    let err = NymError::InvalidSurb;
    assert_eq!(err.as_str(), "Invalid SURB");
}

#[test]
fn test_nym_error_no_available_mixnodes() {
    let err = NymError::NoAvailableMixNodes;
    assert_eq!(err.as_str(), "No available mixnodes");
}

#[test]
fn test_nym_error_no_available_gateways() {
    let err = NymError::NoAvailableGateways;
    assert_eq!(err.as_str(), "No available gateways");
}

#[test]
fn test_nym_error_directory_fetch_failed() {
    let err = NymError::DirectoryFetchFailed;
    assert_eq!(err.as_str(), "Failed to fetch directory");
}

#[test]
fn test_nym_error_timeout() {
    let err = NymError::Timeout;
    assert_eq!(err.as_str(), "Operation timed out");
}

#[test]
fn test_nym_error_socket_error() {
    let err = NymError::SocketError;
    assert_eq!(err.as_str(), "Socket operation failed");
}

#[test]
fn test_nym_error_tls_error() {
    let err = NymError::TlsError;
    assert_eq!(err.as_str(), "TLS error");
}

#[test]
fn test_nym_error_invalid_address() {
    let err = NymError::InvalidAddress;
    assert_eq!(err.as_str(), "Invalid NYM address");
}

#[test]
fn test_nym_error_stream_closed() {
    let err = NymError::StreamClosed;
    assert_eq!(err.as_str(), "Stream is closed");
}

#[test]
fn test_nym_error_buffer_full() {
    let err = NymError::BufferFull;
    assert_eq!(err.as_str(), "Buffer is full");
}

#[test]
fn test_nym_error_internal_error() {
    let err = NymError::InternalError;
    assert_eq!(err.as_str(), "Internal error");
}

#[test]
fn test_nym_error_clone() {
    let err = NymError::Timeout;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_nym_error_copy() {
    let err1 = NymError::ConnectionFailed;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_nym_error_equality() {
    assert_eq!(NymError::Timeout, NymError::Timeout);
    assert_ne!(NymError::Timeout, NymError::SendFailed);
}

#[test]
fn test_nym_error_debug() {
    let err = NymError::HandshakeFailed;
    let debug_str = alloc::format!("{:?}", err);
    assert!(debug_str.contains("HandshakeFailed"));
}

#[test]
fn test_nym_error_all_have_str() {
    let errors = [
        NymError::NotInitialized,
        NymError::AlreadyInitialized,
        NymError::ConnectionFailed,
        NymError::NotConnected,
        NymError::HandshakeFailed,
        NymError::SendFailed,
        NymError::ReceiveFailed,
        NymError::GatewayNotFound,
        NymError::MixNodeNotFound,
        NymError::InvalidRoute,
        NymError::InvalidPacket,
        NymError::PacketTooLarge,
        NymError::EncryptionFailed,
        NymError::DecryptionFailed,
        NymError::InvalidMac,
        NymError::InvalidHeader,
        NymError::InvalidPayload,
        NymError::InvalidSurb,
        NymError::NoAvailableMixNodes,
        NymError::NoAvailableGateways,
        NymError::DirectoryFetchFailed,
        NymError::Timeout,
        NymError::SocketError,
        NymError::TlsError,
        NymError::InvalidAddress,
        NymError::StreamClosed,
        NymError::BufferFull,
        NymError::InternalError,
    ];
    for err in errors {
        assert!(!err.as_str().is_empty());
    }
}

