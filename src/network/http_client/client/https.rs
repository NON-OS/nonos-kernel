// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::helpers::is_response_complete;
use super::http_client::{HttpClient, CONNECTION_POOL, HTTPS_SESSION_CACHE};
use crate::network::http_client::pool::PooledConnection;
use crate::network::http_client::request::{build_request, HttpMethod, MAX_RESPONSE_SIZE};
use crate::network::http_client::response::{find_sequence, parse_response, HttpResponse};
use crate::network::http_client::tls_util::wrap_tls_record;
use crate::network::http_client::url::{resolve_host, ParsedUrl};
use crate::network::onion::tls::TLSConnection;
use alloc::vec::Vec;

impl HttpClient {
    pub(super) fn do_https_request(
        &self,
        url: &ParsedUrl,
        method: HttpMethod,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, &'static str> {
        let ip = resolve_host(&url.host)?;
        let request = build_request(url, method, body, &self.options);
        let stack =
            crate::network::stack::get_network_stack().ok_or("network stack not initialized")?;
        let (conn_id, mut tls) =
            if let Some(pooled) = CONNECTION_POOL.acquire(&url.host, url.port, true) {
                match pooled.tls {
                    Some(tls_conn) => (pooled.conn_id, tls_conn),
                    None => {
                        let _ = stack.tcp_close(pooled.conn_id);
                        create_new_tls_connection(stack, ip, url)?
                    }
                }
            } else {
                create_new_tls_connection(stack, ip, url)?
            };
        let encrypted_request = tls.encrypt_app(&request).map_err(|_| "TLS encrypt failed")?;
        let wrapped = wrap_tls_record(0x17, &encrypted_request);
        if stack.tcp_send(conn_id, &wrapped).is_err() {
            let _ = stack.tcp_close(conn_id);
            let (new_conn_id, mut new_tls) = create_new_tls_connection(stack, ip, url)?;
            let encrypted = new_tls.encrypt_app(&request).map_err(|_| "TLS encrypt failed")?;
            let wrapped = wrap_tls_record(0x17, &encrypted);
            stack.tcp_send(new_conn_id, &wrapped).map_err(|_| "TCP send failed")?;
            return self.receive_https_response(stack, new_conn_id, new_tls, url);
        }
        self.receive_https_response(stack, conn_id, tls, url)
    }

    pub(super) fn receive_https_response(
        &self,
        stack: &crate::network::stack::NetworkStack,
        conn_id: u32,
        mut tls: TLSConnection,
        url: &ParsedUrl,
    ) -> Result<HttpResponse, &'static str> {
        let mut response_data = Vec::new();
        let deadline_ms = crate::time::timestamp_millis() + self.options.timeout_ms;
        loop {
            if crate::time::timestamp_millis() > deadline_ms {
                let _ = stack.tcp_close(conn_id);
                return Err("timeout");
            }
            crate::time::yield_now();
            let received = match stack.tcp_receive(conn_id, 8192) {
                Ok(r) => r,
                Err(_) => {
                    let _ = stack.tcp_close(conn_id);
                    return Err("TCP recv failed");
                }
            };
            if received.is_empty() {
                break;
            }
            let (n, buffer) = (received.len(), &received[..]);
            let mut offset = 0;
            while offset + 5 <= n {
                let content_type = buffer[offset];
                let record_len =
                    u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]) as usize;
                if offset + 5 + record_len > n {
                    break;
                }
                let record_data = &buffer[offset + 5..offset + 5 + record_len];
                if content_type == 0x17 {
                    match tls.decrypt_app(record_data) {
                        Ok(plaintext) => {
                            if !plaintext.is_empty() {
                                response_data.extend_from_slice(&plaintext[..plaintext.len() - 1]);
                            }
                        }
                        Err(_) => {
                            let _ = stack.tcp_close(conn_id);
                            return Err("TLS decrypt failed");
                        }
                    }
                } else if content_type == 0x15 {
                    break;
                }
                offset += 5 + record_len;
            }
            if response_data.len() > 4 {
                if let Some(header_end) = find_sequence(&response_data, b"\r\n\r\n") {
                    if is_response_complete(&response_data, header_end)
                        || response_data.len() > MAX_RESPONSE_SIZE
                    {
                        break;
                    }
                }
            }
        }
        if response_data.is_empty() {
            let _ = stack.tcp_close(conn_id);
            return Err("empty response");
        }
        let response = parse_response(&response_data)?;
        if self.options.keep_alive && response.is_keep_alive() {
            let pooled = PooledConnection {
                conn_id,
                tls: Some(tls),
                last_used_ms: crate::time::timestamp_millis(),
                request_count: 1,
                is_tls: true,
            };
            CONNECTION_POOL.release(&url.host, url.port, pooled, true);
        } else {
            let _ = stack.tcp_close(conn_id);
        }
        Ok(response)
    }
}

pub(super) fn create_new_tls_connection(
    stack: &crate::network::stack::NetworkStack,
    ip: [u8; 4],
    url: &ParsedUrl,
) -> Result<(u32, TLSConnection), &'static str> {
    let stack_socket = crate::network::stack::TcpSocket::new();
    let conn_id = stack_socket.connection_id();
    stack.tcp_connect(&stack_socket, ip, url.port).map_err(|_| "TCP connect failed")?;
    let socket = crate::network::tcp::TcpSocket::from_connection(conn_id);
    let mut tls = TLSConnection::with_session_cache(&HTTPS_SESSION_CACHE);
    let verifier = crate::network::onion::tls::get_cert_verifier()
        .unwrap_or(&crate::network::onion::tls::HTTPS_CERT_VERIFIER);
    let _session_info = tls
        .handshake_full(&socket, Some(&url.host), Some(&["http/1.1"]), verifier)
        .map_err(|_| "TLS handshake failed")?;
    Ok((conn_id, tls))
}
