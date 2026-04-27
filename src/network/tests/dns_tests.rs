// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::dns::types::{
    DnsCacheEntry, DnsQueryRecord, DnsRecord, DnsRecordCacheEntry, DnsRecordType, DnsResponseA,
    DnsResponseAAAA, MxRecord, PendingQuery, SrvRecord, DEFAULT_TTL_MS, MAX_CNAME_DEPTH,
    MAX_QUERY_CACHE,
};
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_max_query_cache_constant() -> TestResult {
    if MAX_QUERY_CACHE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_ttl_ms_constant() -> TestResult {
    if DEFAULT_TTL_MS != 300_000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_cname_depth_constant() -> TestResult {
    if MAX_CNAME_DEPTH != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_a() -> TestResult {
    if DnsRecordType::A as u16 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_ns() -> TestResult {
    if DnsRecordType::NS as u16 != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_cname() -> TestResult {
    if DnsRecordType::CNAME as u16 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_soa() -> TestResult {
    if DnsRecordType::SOA as u16 != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_ptr() -> TestResult {
    if DnsRecordType::PTR as u16 != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_mx() -> TestResult {
    if DnsRecordType::MX as u16 != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_txt() -> TestResult {
    if DnsRecordType::TXT as u16 != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_aaaa() -> TestResult {
    if DnsRecordType::AAAA as u16 != 28 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_srv() -> TestResult {
    if DnsRecordType::SRV as u16 != 33 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_a() -> TestResult {
    if DnsRecordType::from_u16(1) != Some(DnsRecordType::A) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_ns() -> TestResult {
    if DnsRecordType::from_u16(2) != Some(DnsRecordType::NS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_cname() -> TestResult {
    if DnsRecordType::from_u16(5) != Some(DnsRecordType::CNAME) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_soa() -> TestResult {
    if DnsRecordType::from_u16(6) != Some(DnsRecordType::SOA) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_ptr() -> TestResult {
    if DnsRecordType::from_u16(12) != Some(DnsRecordType::PTR) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_mx() -> TestResult {
    if DnsRecordType::from_u16(15) != Some(DnsRecordType::MX) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_txt() -> TestResult {
    if DnsRecordType::from_u16(16) != Some(DnsRecordType::TXT) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_aaaa() -> TestResult {
    if DnsRecordType::from_u16(28) != Some(DnsRecordType::AAAA) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_srv() -> TestResult {
    if DnsRecordType::from_u16(33) != Some(DnsRecordType::SRV) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_from_u16_invalid() -> TestResult {
    if DnsRecordType::from_u16(0) != None {
        return TestResult::Fail;
    }
    if DnsRecordType::from_u16(100) != None {
        return TestResult::Fail;
    }
    if DnsRecordType::from_u16(255) != None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_clone() -> TestResult {
    let t = DnsRecordType::A;
    let cloned = t.clone();
    if t != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_copy() -> TestResult {
    let t1 = DnsRecordType::AAAA;
    let t2 = t1;
    if t1 != t2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_equality() -> TestResult {
    if DnsRecordType::A != DnsRecordType::A {
        return TestResult::Fail;
    }
    if DnsRecordType::A == DnsRecordType::AAAA {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_debug() -> TestResult {
    let t = DnsRecordType::MX;
    let debug_str = alloc::format!("{:?}", t);
    if !debug_str.contains("MX") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mx_record_fields() -> TestResult {
    let mx = MxRecord { preference: 10, exchange: String::from("mail.example.com") };
    if mx.preference != 10 {
        return TestResult::Fail;
    }
    if mx.exchange != "mail.example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mx_record_clone() -> TestResult {
    let mx = MxRecord { preference: 20, exchange: String::from("smtp.test.org") };
    let cloned = mx.clone();
    if mx.preference != cloned.preference {
        return TestResult::Fail;
    }
    if mx.exchange != cloned.exchange {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mx_record_debug() -> TestResult {
    let mx = MxRecord { preference: 5, exchange: String::from("mail.test.com") };
    let debug_str = alloc::format!("{:?}", mx);
    if !debug_str.contains("MxRecord") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_srv_record_fields() -> TestResult {
    let srv =
        SrvRecord { priority: 10, weight: 20, port: 5060, target: String::from("sip.example.com") };
    if srv.priority != 10 {
        return TestResult::Fail;
    }
    if srv.weight != 20 {
        return TestResult::Fail;
    }
    if srv.port != 5060 {
        return TestResult::Fail;
    }
    if srv.target != "sip.example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_srv_record_clone() -> TestResult {
    let srv =
        SrvRecord { priority: 1, weight: 100, port: 443, target: String::from("web.example.com") };
    let cloned = srv.clone();
    if srv.priority != cloned.priority {
        return TestResult::Fail;
    }
    if srv.weight != cloned.weight {
        return TestResult::Fail;
    }
    if srv.port != cloned.port {
        return TestResult::Fail;
    }
    if srv.target != cloned.target {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_a() -> TestResult {
    let record = DnsRecord::A([192, 168, 1, 1]);
    if let DnsRecord::A(addr) = record {
        if addr != [192, 168, 1, 1] {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_aaaa() -> TestResult {
    let record = DnsRecord::AAAA([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    if let DnsRecord::AAAA(addr) = record {
        if addr[0] != 0x20 {
            return TestResult::Fail;
        }
        if addr[15] != 1 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_cname() -> TestResult {
    let record = DnsRecord::CNAME(String::from("www.example.com"));
    if let DnsRecord::CNAME(name) = record {
        if name != "www.example.com" {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_mx() -> TestResult {
    let mx = MxRecord { preference: 10, exchange: String::from("mail.test.com") };
    let record = DnsRecord::MX(mx);
    if let DnsRecord::MX(r) = record {
        if r.preference != 10 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_txt() -> TestResult {
    let record = DnsRecord::TXT(String::from("v=spf1 include:_spf.google.com ~all"));
    if let DnsRecord::TXT(txt) = record {
        if !txt.contains("spf1") {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_ns() -> TestResult {
    let record = DnsRecord::NS(String::from("ns1.example.com"));
    if let DnsRecord::NS(ns) = record {
        if ns != "ns1.example.com" {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_ptr() -> TestResult {
    let record = DnsRecord::PTR(String::from("host.example.com"));
    if let DnsRecord::PTR(ptr) = record {
        if ptr != "host.example.com" {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_srv() -> TestResult {
    let srv =
        SrvRecord { priority: 0, weight: 5, port: 80, target: String::from("web.example.com") };
    let record = DnsRecord::SRV(srv);
    if let DnsRecord::SRV(r) = record {
        if r.port != 80 {
            return TestResult::Fail;
        }
    } else {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_clone() -> TestResult {
    let record = DnsRecord::A([10, 0, 0, 1]);
    let cloned = record.clone();
    if let (DnsRecord::A(a1), DnsRecord::A(a2)) = (record, cloned) {
        if a1 != a2 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_dns_cache_entry_fields() -> TestResult {
    let entry = DnsCacheEntry {
        hostname: String::from("example.com"),
        addresses: vec![[93, 184, 216, 34]],
        timestamp_ms: 1000000,
        ttl_ms: 300000,
    };
    if entry.hostname != "example.com" {
        return TestResult::Fail;
    }
    if entry.addresses.len() != 1 {
        return TestResult::Fail;
    }
    if entry.timestamp_ms != 1000000 {
        return TestResult::Fail;
    }
    if entry.ttl_ms != 300000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_cache_entry_multiple_addresses() -> TestResult {
    let entry = DnsCacheEntry {
        hostname: String::from("multi.example.com"),
        addresses: vec![[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
        timestamp_ms: 500000,
        ttl_ms: 60000,
    };
    if entry.addresses.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_cache_entry_clone() -> TestResult {
    let entry = DnsCacheEntry {
        hostname: String::from("test.com"),
        addresses: vec![[127, 0, 0, 1]],
        timestamp_ms: 0,
        ttl_ms: DEFAULT_TTL_MS,
    };
    let cloned = entry.clone();
    if entry.hostname != cloned.hostname {
        return TestResult::Fail;
    }
    if entry.addresses != cloned.addresses {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_cache_entry_fields() -> TestResult {
    let entry = DnsRecordCacheEntry {
        hostname: String::from("example.org"),
        record_type: DnsRecordType::A,
        records: vec![DnsRecord::A([1, 2, 3, 4])],
        timestamp_ms: 123456,
        ttl_ms: 300000,
    };
    if entry.hostname != "example.org" {
        return TestResult::Fail;
    }
    if entry.record_type != DnsRecordType::A {
        return TestResult::Fail;
    }
    if entry.records.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_cache_entry_clone() -> TestResult {
    let entry = DnsRecordCacheEntry {
        hostname: String::from("test.org"),
        record_type: DnsRecordType::AAAA,
        records: vec![DnsRecord::AAAA([0; 16])],
        timestamp_ms: 0,
        ttl_ms: 60000,
    };
    let cloned = entry.clone();
    if entry.hostname != cloned.hostname {
        return TestResult::Fail;
    }
    if entry.record_type != cloned.record_type {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_query_record_fields() -> TestResult {
    let query = DnsQueryRecord {
        hostname: String::from("query.test.com"),
        timestamp_ms: 999999,
        success: true,
    };
    if query.hostname != "query.test.com" {
        return TestResult::Fail;
    }
    if query.timestamp_ms != 999999 {
        return TestResult::Fail;
    }
    if !query.success {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_query_record_failed() -> TestResult {
    let query = DnsQueryRecord {
        hostname: String::from("failed.test.com"),
        timestamp_ms: 100,
        success: false,
    };
    if query.success {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_query_record_clone() -> TestResult {
    let query = DnsQueryRecord {
        hostname: String::from("clone.test.com"),
        timestamp_ms: 50000,
        success: true,
    };
    let cloned = query.clone();
    if query.hostname != cloned.hostname {
        return TestResult::Fail;
    }
    if query.success != cloned.success {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pending_query_fields() -> TestResult {
    let pending = PendingQuery {
        hostname: String::from("pending.example.com"),
        start_ms: 1000,
        timeout_ms: 5000,
    };
    if pending.hostname != "pending.example.com" {
        return TestResult::Fail;
    }
    if pending.start_ms != 1000 {
        return TestResult::Fail;
    }
    if pending.timeout_ms != 5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pending_query_clone() -> TestResult {
    let pending =
        PendingQuery { hostname: String::from("test.pending.com"), start_ms: 0, timeout_ms: 10000 };
    let cloned = pending.clone();
    if pending.hostname != cloned.hostname {
        return TestResult::Fail;
    }
    if pending.timeout_ms != cloned.timeout_ms {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_response_a_fields() -> TestResult {
    let response = DnsResponseA {
        addresses: vec![[192, 168, 0, 1], [192, 168, 0, 2]],
        ttl_seconds: 3600,
        cnames: vec![String::from("alias.example.com")],
    };
    if response.addresses.len() != 2 {
        return TestResult::Fail;
    }
    if response.ttl_seconds != 3600 {
        return TestResult::Fail;
    }
    if response.cnames.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_response_a_empty() -> TestResult {
    let response = DnsResponseA { addresses: Vec::new(), ttl_seconds: 0, cnames: Vec::new() };
    if !response.addresses.is_empty() {
        return TestResult::Fail;
    }
    if !response.cnames.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_response_a_clone() -> TestResult {
    let response =
        DnsResponseA { addresses: vec![[10, 0, 0, 1]], ttl_seconds: 300, cnames: Vec::new() };
    let cloned = response.clone();
    if response.addresses != cloned.addresses {
        return TestResult::Fail;
    }
    if response.ttl_seconds != cloned.ttl_seconds {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_response_aaaa_fields() -> TestResult {
    let response = DnsResponseAAAA {
        addresses: vec![[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
        ttl_seconds: 7200,
    };
    if response.addresses.len() != 1 {
        return TestResult::Fail;
    }
    if response.ttl_seconds != 7200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_response_aaaa_empty() -> TestResult {
    let response = DnsResponseAAAA { addresses: Vec::new(), ttl_seconds: 0 };
    if !response.addresses.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_response_aaaa_clone() -> TestResult {
    let response = DnsResponseAAAA { addresses: vec![[0; 16]], ttl_seconds: 600 };
    let cloned = response.clone();
    if response.addresses != cloned.addresses {
        return TestResult::Fail;
    }
    if response.ttl_seconds != cloned.ttl_seconds {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dns_record_type_all_values() -> TestResult {
    let types = [
        (DnsRecordType::A, 1u16),
        (DnsRecordType::NS, 2),
        (DnsRecordType::CNAME, 5),
        (DnsRecordType::SOA, 6),
        (DnsRecordType::PTR, 12),
        (DnsRecordType::MX, 15),
        (DnsRecordType::TXT, 16),
        (DnsRecordType::AAAA, 28),
        (DnsRecordType::SRV, 33),
    ];
    for (t, v) in types {
        if t as u16 != v {
            return TestResult::Fail;
        }
        if DnsRecordType::from_u16(v) != Some(t) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
