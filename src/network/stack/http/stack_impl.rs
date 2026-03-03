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

extern crate alloc;

use alloc::vec::Vec;

use super::super::core::NetworkStack;
use super::super::device::now_ms;
use super::super::types::TcpSocket;
use super::super::util::{find_subsequence, starts_no_case, parse_usize_ascii};
use super::chunked::{decode_chunked, is_chunked_complete};

fn wrap_tls_record(content_type: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut record = Vec::with_capacity(5 + len);
    record.push(content_type);
    record.push(0x03);
    record.push(0x03);
    record.push((len >> 8) as u8);
    record.push((len & 0xff) as u8);
    record.extend_from_slice(data);
    record
}

impl NetworkStack {
    pub fn https_request(&self, addr: [u8; 4], port: u16, host: &str, req: &[u8], _timeout_ms: u32) -> Result<Vec<u8>, &'static str> {
        use crate::network::onion::tls::{TLSConnection, get_cert_verifier};
        use crate::network::tcp::TcpSocket as TlsTcpSocket;
        use super::super::types::TcpSocket;

        let stack_sock = TcpSocket::new();
        self.tcp_connect(&stack_sock, addr, port)?;
        let conn_id = stack_sock.connection_id();

        let tls_sock = TlsTcpSocket::from_connection(conn_id);

        let verifier = get_cert_verifier().ok_or("no cert verifier")?;
        let mut tls = TLSConnection::new();
        tls.handshake_full(&tls_sock, Some(host), None, verifier)
            .map_err(|_| "tls handshake failed")?;

        let encrypted_req = tls.encrypt_app(req)
            .map_err(|_| "tls encrypt failed")?;
        let record = wrap_tls_record(0x17, &encrypted_req);
        self.tcp_send(conn_id, &record)?;

        const CAP: usize = 5 * 1024 * 1024;
        let mut plaintext_buf = Vec::with_capacity(4096);
        let mut headers_done = false;
        let mut content_length: Option<usize> = None;
        let start = now_ms();

        for _ in 0..5000 {
            let chunk = self.tcp_receive(conn_id, 4096)?;
            if !chunk.is_empty() {
                let mut cur = chunk.as_slice();
                while cur.len() >= 5 {
                    let ct = cur[0];
                    let len = u16::from_be_bytes([cur[3], cur[4]]) as usize;
                    if cur.len() < 5 + len {
                        break;
                    }
                    let body = &cur[5..5 + len];

                    if ct == 0x17 {
                        if let Ok(decrypted) = tls.decrypt_app(body) {
                            if plaintext_buf.len() + decrypted.len() <= CAP {
                                plaintext_buf.extend_from_slice(&decrypted);
                            }
                        }
                    }
                    cur = &cur[5 + len..];
                }
            }

            if !headers_done {
                if let Some(idx) = find_subsequence(&plaintext_buf, b"\r\n\r\n") {
                    headers_done = true;
                    let headers = &plaintext_buf[..idx + 4];
                    for line in headers.split(|&b| b == b'\n') {
                        if line.len() >= 18 && starts_no_case(line, b"content-length:") {
                            if let Ok(n) = parse_usize_ascii(&line[15..]) {
                                content_length = Some(n);
                            }
                        }
                    }
                    if let Some(n) = content_length {
                        if plaintext_buf.len() - (idx + 4) >= n {
                            break;
                        }
                    }
                }
            } else if let Some(n) = content_length {
                if let Some(idx) = find_subsequence(&plaintext_buf, b"\r\n\r\n") {
                    if plaintext_buf.len() - (idx + 4) >= n {
                        break;
                    }
                }
            }

            if now_ms().saturating_sub(start) > 10_000 {
                break;
            }

            self.poll();
            crate::time::yield_now();
        }

        let _ = self.tcp_close(conn_id);
        Ok(plaintext_buf)
    }

    pub fn http_request(&self, addr: [u8; 4], port: u16, req: &[u8]) -> Result<Vec<u8>, &'static str> {
        let tmp = TcpSocket::new();
        self.tcp_connect(&tmp, addr, port)?;
        let id = tmp.connection_id();
        let _ = self.tcp_send(id, req)?;

        const CAP: usize = 5 * 1024 * 1024;
        const MAX_ITERATIONS: u32 = 5_000;
        let mut buf = Vec::with_capacity(4096);
        let mut headers_done = false;
        let mut content_length: Option<usize> = None;
        let mut is_chunked = false;
        let start = now_ms();
        let mut iterations = 0u32;

        loop {
            let chunk = self.tcp_receive(id, 4096)?;
            if !chunk.is_empty() {
                if buf.len() + chunk.len() > CAP { let _ = self.tcp_close(id); return Err("http cap exceeded"); }
                buf.extend_from_slice(&chunk);
            }
            if !headers_done {
                if let Some(idx) = find_subsequence(&buf, b"\r\n\r\n") {
                    headers_done = true;
                    let headers = &buf[..idx+4];
                    if !headers.starts_with(b"HTTP/1.1 200") && !headers.starts_with(b"HTTP/1.0 200") &&
                       !headers.starts_with(b"HTTP/1.1 2") && !headers.starts_with(b"HTTP/1.0 2") {
                        let _ = self.tcp_close(id);
                        return Err("http non-2xx");
                    }
                    for line in headers.split(|&b| b == b'\n') {
                        if line.len() >= 18 && starts_no_case(line, b"content-length:") {
                            if let Ok(n) = parse_usize_ascii(&line[15..]) { content_length = Some(n); }
                        }
                        if starts_no_case(line, b"transfer-encoding:") {
                            let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
                            if find_subsequence(&lower, b"chunked").is_some() {
                                is_chunked = true;
                            }
                        }
                    }

                    if let Some(n) = content_length {
                        if buf.len() - (idx + 4) >= n { break; }
                    }

                    if is_chunked {
                        if let Some(body_start) = find_subsequence(&buf, b"\r\n\r\n") {
                            let body = &buf[body_start + 4..];
                            if is_chunked_complete(body) { break; }
                        }
                    }
                }
            } else if is_chunked {
                if let Some(body_start) = find_subsequence(&buf, b"\r\n\r\n") {
                    let body = &buf[body_start + 4..];
                    if is_chunked_complete(body) { break; }
                }
            } else if let Some(n) = content_length {
                if let Some(idx) = find_subsequence(&buf, b"\r\n\r\n") {
                    if buf.len() - (idx + 4) >= n { break; }
                }
            }

            if now_ms().saturating_sub(start) > 2_000 { break; }

            iterations += 1;
            if iterations >= MAX_ITERATIONS { break; }

            self.poll();
            crate::time::yield_now();
        }
        let _ = self.tcp_close(id);

        if is_chunked {
            if let Some(body_start) = find_subsequence(&buf, b"\r\n\r\n") {
                let headers = buf[..body_start + 4].to_vec();
                let body = decode_chunked(&buf[body_start + 4..]);
                let mut result = headers;
                result.extend_from_slice(&body);
                return Ok(result);
            }
        }

        Ok(buf)
    }
}
