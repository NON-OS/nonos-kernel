// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::nym::error::NymError;
use crate::network::nym::types::address::NymAddress;
use crate::network::nym::types::constants::{
    NYM_CONNECT_TIMEOUT_MS, NYM_COVER_INTERVAL_MS, NYM_DEFAULT_GATEWAY_PORT, NYM_DEFAULT_MIX_PORT,
    NYM_FRAGMENT_SIZE, NYM_HEADER_SIZE, NYM_KEY_SIZE, NYM_MAC_SIZE, NYM_MAX_HOPS, NYM_MIX_LAYERS,
    NYM_NODE_ADDRESS_SIZE, NYM_NONCE_SIZE, NYM_PACKET_SIZE, NYM_PAYLOAD_SIZE, NYM_READ_TIMEOUT_MS,
    NYM_ROUTING_INFO_SIZE, NYM_SURB_SIZE, NYM_TAG_SIZE, NYM_WRITE_TIMEOUT_MS,
};
use crate::network::nym::types::ids::{ClientId, GatewayId, MixNodeId, SurbId};
use crate::test::framework::TestResult;

pub(crate) fn test_nym_packet_size() -> TestResult {
    if NYM_PACKET_SIZE != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_payload_size() -> TestResult {
    if NYM_PAYLOAD_SIZE != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_header_size() -> TestResult {
    if NYM_HEADER_SIZE != 816 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_mac_size() -> TestResult {
    if NYM_MAC_SIZE != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_routing_info_size() -> TestResult {
    if NYM_ROUTING_INFO_SIZE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_mix_layers() -> TestResult {
    if NYM_MIX_LAYERS != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_cover_interval_ms() -> TestResult {
    if NYM_COVER_INTERVAL_MS != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_key_size() -> TestResult {
    if NYM_KEY_SIZE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_nonce_size() -> TestResult {
    if NYM_NONCE_SIZE != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_tag_size() -> TestResult {
    if NYM_TAG_SIZE != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_node_address_size() -> TestResult {
    if NYM_NODE_ADDRESS_SIZE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_surb_size() -> TestResult {
    if NYM_SURB_SIZE != 296 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_fragment_size() -> TestResult {
    if NYM_FRAGMENT_SIZE != 500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_max_hops() -> TestResult {
    if NYM_MAX_HOPS != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_default_gateway_port() -> TestResult {
    if NYM_DEFAULT_GATEWAY_PORT != 9000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_default_mix_port() -> TestResult {
    if NYM_DEFAULT_MIX_PORT != 1789 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_connect_timeout_ms() -> TestResult {
    if NYM_CONNECT_TIMEOUT_MS != 15000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_read_timeout_ms() -> TestResult {
    if NYM_READ_TIMEOUT_MS != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_write_timeout_ms() -> TestResult {
    if NYM_WRITE_TIMEOUT_MS != 10000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_packet_structure() -> TestResult {
    if !(NYM_HEADER_SIZE + NYM_PAYLOAD_SIZE <= NYM_PACKET_SIZE) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_max_hops_equals_mix_layers() -> TestResult {
    if NYM_MAX_HOPS != NYM_MIX_LAYERS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_from_bytes() -> TestResult {
    let bytes = [1u8; 32];
    let id = MixNodeId::from_bytes(&bytes);
    if !id.is_some() {
        return TestResult::Fail;
    }
    if id.unwrap().0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_from_bytes_wrong_size() -> TestResult {
    let bytes = [1u8; 16];
    let id = MixNodeId::from_bytes(&bytes);
    if !id.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_as_bytes() -> TestResult {
    let bytes = [42u8; 32];
    let id = MixNodeId(bytes);
    if id.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_clone() -> TestResult {
    let id = MixNodeId([0xAB; 32]);
    let cloned = id.clone();
    if id != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_copy() -> TestResult {
    let id1 = MixNodeId([0xCD; 32]);
    let id2 = id1;
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_equality() -> TestResult {
    let id1 = MixNodeId([1; 32]);
    let id2 = MixNodeId([1; 32]);
    let id3 = MixNodeId([2; 32]);
    if id1 != id2 {
        return TestResult::Fail;
    }
    if id1 == id3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mixnode_id_ordering() -> TestResult {
    let id1 = MixNodeId([1; 32]);
    let id2 = MixNodeId([2; 32]);
    if !(id1 < id2) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gateway_id_from_bytes() -> TestResult {
    let bytes = [0xFF; 32];
    let id = GatewayId::from_bytes(&bytes);
    if !id.is_some() {
        return TestResult::Fail;
    }
    if id.unwrap().0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gateway_id_from_bytes_wrong_size() -> TestResult {
    let bytes = [0xFF; 64];
    let id = GatewayId::from_bytes(&bytes);
    if !id.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gateway_id_as_bytes() -> TestResult {
    let bytes = [0x11; 32];
    let id = GatewayId(bytes);
    if id.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gateway_id_clone() -> TestResult {
    let id = GatewayId([0x22; 32]);
    let cloned = id.clone();
    if id != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gateway_id_copy() -> TestResult {
    let id1 = GatewayId([0x33; 32]);
    let id2 = id1;
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_gateway_id_equality() -> TestResult {
    let id1 = GatewayId([5; 32]);
    let id2 = GatewayId([5; 32]);
    let id3 = GatewayId([6; 32]);
    if id1 != id2 {
        return TestResult::Fail;
    }
    if id1 == id3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_id_from_bytes() -> TestResult {
    let bytes = [0xAA; 32];
    let id = ClientId::from_bytes(&bytes);
    if !id.is_some() {
        return TestResult::Fail;
    }
    if id.unwrap().0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_id_from_bytes_wrong_size() -> TestResult {
    let bytes = [0xAA; 31];
    let id = ClientId::from_bytes(&bytes);
    if !id.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_id_as_bytes() -> TestResult {
    let bytes = [0xBB; 32];
    let id = ClientId(bytes);
    if id.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_id_clone() -> TestResult {
    let id = ClientId([0xCC; 32]);
    let cloned = id.clone();
    if id != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_client_id_copy() -> TestResult {
    let id1 = ClientId([0xDD; 32]);
    let id2 = id1;
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_surb_id_from_bytes() -> TestResult {
    let bytes = [0x12; 16];
    let id = SurbId::from_bytes(&bytes);
    if !id.is_some() {
        return TestResult::Fail;
    }
    if id.unwrap().0 != bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_surb_id_from_bytes_wrong_size() -> TestResult {
    let bytes = [0x12; 32];
    let id = SurbId::from_bytes(&bytes);
    if !id.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_surb_id_as_bytes() -> TestResult {
    let bytes = [0x34; 16];
    let id = SurbId(bytes);
    if id.as_bytes() != &bytes {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_surb_id_clone() -> TestResult {
    let id = SurbId([0x56; 16]);
    let cloned = id.clone();
    if id != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_surb_id_copy() -> TestResult {
    let id1 = SurbId([0x78; 16]);
    let id2 = id1;
    if id1 != id2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_new() -> TestResult {
    let gateway = GatewayId([1; 32]);
    let client = ClientId([2; 32]);
    let addr = NymAddress::new(gateway, client);
    if addr.gateway != gateway {
        return TestResult::Fail;
    }
    if addr.client_id != client {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_to_bytes() -> TestResult {
    let gateway = GatewayId([0xAA; 32]);
    let client = ClientId([0xBB; 32]);
    let addr = NymAddress::new(gateway, client);
    let bytes = addr.to_bytes();
    if bytes.len() != 64 {
        return TestResult::Fail;
    }
    if &bytes[..32] != &[0xAA; 32] {
        return TestResult::Fail;
    }
    if &bytes[32..] != &[0xBB; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_from_bytes() -> TestResult {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&[0x11; 32]);
    bytes[32..].copy_from_slice(&[0x22; 32]);
    let addr = NymAddress::from_bytes(&bytes);
    if !addr.is_some() {
        return TestResult::Fail;
    }
    let addr = addr.unwrap();
    if addr.gateway.0 != [0x11; 32] {
        return TestResult::Fail;
    }
    if addr.client_id.0 != [0x22; 32] {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_from_bytes_wrong_size() -> TestResult {
    let bytes = [0u8; 32];
    let addr = NymAddress::from_bytes(&bytes);
    if !addr.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_roundtrip() -> TestResult {
    let gateway = GatewayId([0x55; 32]);
    let client = ClientId([0x66; 32]);
    let original = NymAddress::new(gateway, client);
    let bytes = original.to_bytes();
    let restored = NymAddress::from_bytes(&bytes).unwrap();
    if original != restored {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_clone() -> TestResult {
    let addr = NymAddress::new(GatewayId([1; 32]), ClientId([2; 32]));
    let cloned = addr.clone();
    if addr != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_address_equality() -> TestResult {
    let addr1 = NymAddress::new(GatewayId([1; 32]), ClientId([2; 32]));
    let addr2 = NymAddress::new(GatewayId([1; 32]), ClientId([2; 32]));
    let addr3 = NymAddress::new(GatewayId([3; 32]), ClientId([2; 32]));
    if addr1 != addr2 {
        return TestResult::Fail;
    }
    if addr1 == addr3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_not_initialized() -> TestResult {
    let err = NymError::NotInitialized;
    if err.as_str() != "NYM client not initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_already_initialized() -> TestResult {
    let err = NymError::AlreadyInitialized;
    if err.as_str() != "NYM client already initialized" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_connection_failed() -> TestResult {
    let err = NymError::ConnectionFailed;
    if err.as_str() != "Failed to connect to gateway" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_not_connected() -> TestResult {
    let err = NymError::NotConnected;
    if err.as_str() != "Not connected to gateway" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_handshake_failed() -> TestResult {
    let err = NymError::HandshakeFailed;
    if err.as_str() != "Gateway handshake failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_send_failed() -> TestResult {
    let err = NymError::SendFailed;
    if err.as_str() != "Failed to send data" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_receive_failed() -> TestResult {
    let err = NymError::ReceiveFailed;
    if err.as_str() != "Failed to receive data" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_gateway_not_found() -> TestResult {
    let err = NymError::GatewayNotFound;
    if err.as_str() != "Gateway not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_mixnode_not_found() -> TestResult {
    let err = NymError::MixNodeNotFound;
    if err.as_str() != "MixNode not found" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_route() -> TestResult {
    let err = NymError::InvalidRoute;
    if err.as_str() != "Invalid route through mixnet" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_packet() -> TestResult {
    let err = NymError::InvalidPacket;
    if err.as_str() != "Invalid Sphinx packet" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_packet_too_large() -> TestResult {
    let err = NymError::PacketTooLarge;
    if err.as_str() != "Packet payload too large" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_encryption_failed() -> TestResult {
    let err = NymError::EncryptionFailed;
    if err.as_str() != "Sphinx encryption failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_decryption_failed() -> TestResult {
    let err = NymError::DecryptionFailed;
    if err.as_str() != "Sphinx decryption failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_mac() -> TestResult {
    let err = NymError::InvalidMac;
    if err.as_str() != "Invalid MAC on packet" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_header() -> TestResult {
    let err = NymError::InvalidHeader;
    if err.as_str() != "Invalid Sphinx header" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_payload() -> TestResult {
    let err = NymError::InvalidPayload;
    if err.as_str() != "Invalid packet payload" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_surb() -> TestResult {
    let err = NymError::InvalidSurb;
    if err.as_str() != "Invalid SURB" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_no_available_mixnodes() -> TestResult {
    let err = NymError::NoAvailableMixNodes;
    if err.as_str() != "No available mixnodes" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_no_available_gateways() -> TestResult {
    let err = NymError::NoAvailableGateways;
    if err.as_str() != "No available gateways" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_directory_fetch_failed() -> TestResult {
    let err = NymError::DirectoryFetchFailed;
    if err.as_str() != "Failed to fetch directory" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_timeout() -> TestResult {
    let err = NymError::Timeout;
    if err.as_str() != "Operation timed out" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_socket_error() -> TestResult {
    let err = NymError::SocketError;
    if err.as_str() != "Socket operation failed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_tls_error() -> TestResult {
    let err = NymError::TlsError;
    if err.as_str() != "TLS error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_invalid_address() -> TestResult {
    let err = NymError::InvalidAddress;
    if err.as_str() != "Invalid NYM address" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_stream_closed() -> TestResult {
    let err = NymError::StreamClosed;
    if err.as_str() != "Stream is closed" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_buffer_full() -> TestResult {
    let err = NymError::BufferFull;
    if err.as_str() != "Buffer is full" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_internal_error() -> TestResult {
    let err = NymError::InternalError;
    if err.as_str() != "Internal error" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_clone() -> TestResult {
    let err = NymError::Timeout;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_copy() -> TestResult {
    let err1 = NymError::ConnectionFailed;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_equality() -> TestResult {
    if NymError::Timeout != NymError::Timeout {
        return TestResult::Fail;
    }
    if NymError::Timeout == NymError::SendFailed {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_debug() -> TestResult {
    let err = NymError::HandshakeFailed;
    let debug_str = alloc::format!("{:?}", err);
    if !debug_str.contains("HandshakeFailed") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nym_error_all_have_str() -> TestResult {
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
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
