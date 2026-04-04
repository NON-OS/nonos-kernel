// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::network::dns::types::{
    DnsRecordType, MxRecord, SrvRecord, DnsRecord, DnsCacheEntry,
    DnsRecordCacheEntry, DnsQueryRecord, PendingQuery, DnsResponseA,
    DnsResponseAAAA, MAX_QUERY_CACHE, DEFAULT_TTL_MS, MAX_CNAME_DEPTH,
};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::vec;

#[test]
fn test_max_query_cache_constant() {
    assert_eq!(MAX_QUERY_CACHE, 64);
}

#[test]
fn test_default_ttl_ms_constant() {
    assert_eq!(DEFAULT_TTL_MS, 300_000);
}

#[test]
fn test_max_cname_depth_constant() {
    assert_eq!(MAX_CNAME_DEPTH, 8);
}

#[test]
fn test_dns_record_type_a() {
    assert_eq!(DnsRecordType::A as u16, 1);
}

#[test]
fn test_dns_record_type_ns() {
    assert_eq!(DnsRecordType::NS as u16, 2);
}

#[test]
fn test_dns_record_type_cname() {
    assert_eq!(DnsRecordType::CNAME as u16, 5);
}

#[test]
fn test_dns_record_type_soa() {
    assert_eq!(DnsRecordType::SOA as u16, 6);
}

#[test]
fn test_dns_record_type_ptr() {
    assert_eq!(DnsRecordType::PTR as u16, 12);
}

#[test]
fn test_dns_record_type_mx() {
    assert_eq!(DnsRecordType::MX as u16, 15);
}

#[test]
fn test_dns_record_type_txt() {
    assert_eq!(DnsRecordType::TXT as u16, 16);
}

#[test]
fn test_dns_record_type_aaaa() {
    assert_eq!(DnsRecordType::AAAA as u16, 28);
}

#[test]
fn test_dns_record_type_srv() {
    assert_eq!(DnsRecordType::SRV as u16, 33);
}

#[test]
fn test_dns_record_type_from_u16_a() {
    assert_eq!(DnsRecordType::from_u16(1), Some(DnsRecordType::A));
}

#[test]
fn test_dns_record_type_from_u16_ns() {
    assert_eq!(DnsRecordType::from_u16(2), Some(DnsRecordType::NS));
}

#[test]
fn test_dns_record_type_from_u16_cname() {
    assert_eq!(DnsRecordType::from_u16(5), Some(DnsRecordType::CNAME));
}

#[test]
fn test_dns_record_type_from_u16_soa() {
    assert_eq!(DnsRecordType::from_u16(6), Some(DnsRecordType::SOA));
}

#[test]
fn test_dns_record_type_from_u16_ptr() {
    assert_eq!(DnsRecordType::from_u16(12), Some(DnsRecordType::PTR));
}

#[test]
fn test_dns_record_type_from_u16_mx() {
    assert_eq!(DnsRecordType::from_u16(15), Some(DnsRecordType::MX));
}

#[test]
fn test_dns_record_type_from_u16_txt() {
    assert_eq!(DnsRecordType::from_u16(16), Some(DnsRecordType::TXT));
}

#[test]
fn test_dns_record_type_from_u16_aaaa() {
    assert_eq!(DnsRecordType::from_u16(28), Some(DnsRecordType::AAAA));
}

#[test]
fn test_dns_record_type_from_u16_srv() {
    assert_eq!(DnsRecordType::from_u16(33), Some(DnsRecordType::SRV));
}

#[test]
fn test_dns_record_type_from_u16_invalid() {
    assert_eq!(DnsRecordType::from_u16(0), None);
    assert_eq!(DnsRecordType::from_u16(100), None);
    assert_eq!(DnsRecordType::from_u16(255), None);
}

#[test]
fn test_dns_record_type_clone() {
    let t = DnsRecordType::A;
    let cloned = t.clone();
    assert_eq!(t, cloned);
}

#[test]
fn test_dns_record_type_copy() {
    let t1 = DnsRecordType::AAAA;
    let t2 = t1;
    assert_eq!(t1, t2);
}

#[test]
fn test_dns_record_type_equality() {
    assert_eq!(DnsRecordType::A, DnsRecordType::A);
    assert_ne!(DnsRecordType::A, DnsRecordType::AAAA);
}

#[test]
fn test_dns_record_type_debug() {
    let t = DnsRecordType::MX;
    let debug_str = alloc::format!("{:?}", t);
    assert!(debug_str.contains("MX"));
}

#[test]
fn test_mx_record_fields() {
    let mx = MxRecord {
        preference: 10,
        exchange: String::from("mail.example.com"),
    };
    assert_eq!(mx.preference, 10);
    assert_eq!(mx.exchange, "mail.example.com");
}

#[test]
fn test_mx_record_clone() {
    let mx = MxRecord {
        preference: 20,
        exchange: String::from("smtp.test.org"),
    };
    let cloned = mx.clone();
    assert_eq!(mx.preference, cloned.preference);
    assert_eq!(mx.exchange, cloned.exchange);
}

#[test]
fn test_mx_record_debug() {
    let mx = MxRecord {
        preference: 5,
        exchange: String::from("mail.test.com"),
    };
    let debug_str = alloc::format!("{:?}", mx);
    assert!(debug_str.contains("MxRecord"));
}

#[test]
fn test_srv_record_fields() {
    let srv = SrvRecord {
        priority: 10,
        weight: 20,
        port: 5060,
        target: String::from("sip.example.com"),
    };
    assert_eq!(srv.priority, 10);
    assert_eq!(srv.weight, 20);
    assert_eq!(srv.port, 5060);
    assert_eq!(srv.target, "sip.example.com");
}

#[test]
fn test_srv_record_clone() {
    let srv = SrvRecord {
        priority: 1,
        weight: 100,
        port: 443,
        target: String::from("web.example.com"),
    };
    let cloned = srv.clone();
    assert_eq!(srv.priority, cloned.priority);
    assert_eq!(srv.weight, cloned.weight);
    assert_eq!(srv.port, cloned.port);
    assert_eq!(srv.target, cloned.target);
}

#[test]
fn test_dns_record_a() {
    let record = DnsRecord::A([192, 168, 1, 1]);
    if let DnsRecord::A(addr) = record {
        assert_eq!(addr, [192, 168, 1, 1]);
    } else {
        panic!("Expected A record");
    }
}

#[test]
fn test_dns_record_aaaa() {
    let record = DnsRecord::AAAA([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    if let DnsRecord::AAAA(addr) = record {
        assert_eq!(addr[0], 0x20);
        assert_eq!(addr[15], 1);
    } else {
        panic!("Expected AAAA record");
    }
}

#[test]
fn test_dns_record_cname() {
    let record = DnsRecord::CNAME(String::from("www.example.com"));
    if let DnsRecord::CNAME(name) = record {
        assert_eq!(name, "www.example.com");
    } else {
        panic!("Expected CNAME record");
    }
}

#[test]
fn test_dns_record_mx() {
    let mx = MxRecord {
        preference: 10,
        exchange: String::from("mail.test.com"),
    };
    let record = DnsRecord::MX(mx);
    if let DnsRecord::MX(r) = record {
        assert_eq!(r.preference, 10);
    } else {
        panic!("Expected MX record");
    }
}

#[test]
fn test_dns_record_txt() {
    let record = DnsRecord::TXT(String::from("v=spf1 include:_spf.google.com ~all"));
    if let DnsRecord::TXT(txt) = record {
        assert!(txt.contains("spf1"));
    } else {
        panic!("Expected TXT record");
    }
}

#[test]
fn test_dns_record_ns() {
    let record = DnsRecord::NS(String::from("ns1.example.com"));
    if let DnsRecord::NS(ns) = record {
        assert_eq!(ns, "ns1.example.com");
    } else {
        panic!("Expected NS record");
    }
}

#[test]
fn test_dns_record_ptr() {
    let record = DnsRecord::PTR(String::from("host.example.com"));
    if let DnsRecord::PTR(ptr) = record {
        assert_eq!(ptr, "host.example.com");
    } else {
        panic!("Expected PTR record");
    }
}

#[test]
fn test_dns_record_srv() {
    let srv = SrvRecord {
        priority: 0,
        weight: 5,
        port: 80,
        target: String::from("web.example.com"),
    };
    let record = DnsRecord::SRV(srv);
    if let DnsRecord::SRV(r) = record {
        assert_eq!(r.port, 80);
    } else {
        panic!("Expected SRV record");
    }
}

#[test]
fn test_dns_record_clone() {
    let record = DnsRecord::A([10, 0, 0, 1]);
    let cloned = record.clone();
    if let (DnsRecord::A(a1), DnsRecord::A(a2)) = (record, cloned) {
        assert_eq!(a1, a2);
    }
}

#[test]
fn test_dns_cache_entry_fields() {
    let entry = DnsCacheEntry {
        hostname: String::from("example.com"),
        addresses: vec![[93, 184, 216, 34]],
        timestamp_ms: 1000000,
        ttl_ms: 300000,
    };
    assert_eq!(entry.hostname, "example.com");
    assert_eq!(entry.addresses.len(), 1);
    assert_eq!(entry.timestamp_ms, 1000000);
    assert_eq!(entry.ttl_ms, 300000);
}

#[test]
fn test_dns_cache_entry_multiple_addresses() {
    let entry = DnsCacheEntry {
        hostname: String::from("multi.example.com"),
        addresses: vec![[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
        timestamp_ms: 500000,
        ttl_ms: 60000,
    };
    assert_eq!(entry.addresses.len(), 3);
}

#[test]
fn test_dns_cache_entry_clone() {
    let entry = DnsCacheEntry {
        hostname: String::from("test.com"),
        addresses: vec![[127, 0, 0, 1]],
        timestamp_ms: 0,
        ttl_ms: DEFAULT_TTL_MS,
    };
    let cloned = entry.clone();
    assert_eq!(entry.hostname, cloned.hostname);
    assert_eq!(entry.addresses, cloned.addresses);
}

#[test]
fn test_dns_record_cache_entry_fields() {
    let entry = DnsRecordCacheEntry {
        hostname: String::from("example.org"),
        record_type: DnsRecordType::A,
        records: vec![DnsRecord::A([1, 2, 3, 4])],
        timestamp_ms: 123456,
        ttl_ms: 300000,
    };
    assert_eq!(entry.hostname, "example.org");
    assert_eq!(entry.record_type, DnsRecordType::A);
    assert_eq!(entry.records.len(), 1);
}

#[test]
fn test_dns_record_cache_entry_clone() {
    let entry = DnsRecordCacheEntry {
        hostname: String::from("test.org"),
        record_type: DnsRecordType::AAAA,
        records: vec![DnsRecord::AAAA([0; 16])],
        timestamp_ms: 0,
        ttl_ms: 60000,
    };
    let cloned = entry.clone();
    assert_eq!(entry.hostname, cloned.hostname);
    assert_eq!(entry.record_type, cloned.record_type);
}

#[test]
fn test_dns_query_record_fields() {
    let query = DnsQueryRecord {
        hostname: String::from("query.test.com"),
        timestamp_ms: 999999,
        success: true,
    };
    assert_eq!(query.hostname, "query.test.com");
    assert_eq!(query.timestamp_ms, 999999);
    assert!(query.success);
}

#[test]
fn test_dns_query_record_failed() {
    let query = DnsQueryRecord {
        hostname: String::from("failed.test.com"),
        timestamp_ms: 100,
        success: false,
    };
    assert!(!query.success);
}

#[test]
fn test_dns_query_record_clone() {
    let query = DnsQueryRecord {
        hostname: String::from("clone.test.com"),
        timestamp_ms: 50000,
        success: true,
    };
    let cloned = query.clone();
    assert_eq!(query.hostname, cloned.hostname);
    assert_eq!(query.success, cloned.success);
}

#[test]
fn test_pending_query_fields() {
    let pending = PendingQuery {
        hostname: String::from("pending.example.com"),
        start_ms: 1000,
        timeout_ms: 5000,
    };
    assert_eq!(pending.hostname, "pending.example.com");
    assert_eq!(pending.start_ms, 1000);
    assert_eq!(pending.timeout_ms, 5000);
}

#[test]
fn test_pending_query_clone() {
    let pending = PendingQuery {
        hostname: String::from("test.pending.com"),
        start_ms: 0,
        timeout_ms: 10000,
    };
    let cloned = pending.clone();
    assert_eq!(pending.hostname, cloned.hostname);
    assert_eq!(pending.timeout_ms, cloned.timeout_ms);
}

#[test]
fn test_dns_response_a_fields() {
    let response = DnsResponseA {
        addresses: vec![[192, 168, 0, 1], [192, 168, 0, 2]],
        ttl_seconds: 3600,
        cnames: vec![String::from("alias.example.com")],
    };
    assert_eq!(response.addresses.len(), 2);
    assert_eq!(response.ttl_seconds, 3600);
    assert_eq!(response.cnames.len(), 1);
}

#[test]
fn test_dns_response_a_empty() {
    let response = DnsResponseA {
        addresses: Vec::new(),
        ttl_seconds: 0,
        cnames: Vec::new(),
    };
    assert!(response.addresses.is_empty());
    assert!(response.cnames.is_empty());
}

#[test]
fn test_dns_response_a_clone() {
    let response = DnsResponseA {
        addresses: vec![[10, 0, 0, 1]],
        ttl_seconds: 300,
        cnames: Vec::new(),
    };
    let cloned = response.clone();
    assert_eq!(response.addresses, cloned.addresses);
    assert_eq!(response.ttl_seconds, cloned.ttl_seconds);
}

#[test]
fn test_dns_response_aaaa_fields() {
    let response = DnsResponseAAAA {
        addresses: vec![[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]],
        ttl_seconds: 7200,
    };
    assert_eq!(response.addresses.len(), 1);
    assert_eq!(response.ttl_seconds, 7200);
}

#[test]
fn test_dns_response_aaaa_empty() {
    let response = DnsResponseAAAA {
        addresses: Vec::new(),
        ttl_seconds: 0,
    };
    assert!(response.addresses.is_empty());
}

#[test]
fn test_dns_response_aaaa_clone() {
    let response = DnsResponseAAAA {
        addresses: vec![[0; 16]],
        ttl_seconds: 600,
    };
    let cloned = response.clone();
    assert_eq!(response.addresses, cloned.addresses);
    assert_eq!(response.ttl_seconds, cloned.ttl_seconds);
}

#[test]
fn test_dns_record_type_all_values() {
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
        assert_eq!(t as u16, v);
        assert_eq!(DnsRecordType::from_u16(v), Some(t));
    }
}

