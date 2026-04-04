// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Tests for agents/memory.rs - AgentMemory, MemoryEntry

use crate::agents::memory::{AgentMemory, MemoryEntry, MAX_ENTRIES};

#[test]
fn test_memory_new() {
    let mem = AgentMemory::new(1);
    assert_eq!(mem.agent_id, 1);
}

#[test]
fn test_memory_store_and_recall() {
    let mem = AgentMemory::new(100);

    mem.store(b"test_key", b"test_value", 5);

    let recalled = mem.recall(b"test_key");
    assert!(recalled.is_some());
    assert_eq!(recalled.unwrap().as_slice(), b"test_value");
}

#[test]
fn test_memory_recall_nonexistent() {
    let mem = AgentMemory::new(100);

    let recalled = mem.recall(b"nonexistent");
    assert!(recalled.is_none());
}

#[test]
fn test_memory_store_update_existing() {
    let mem = AgentMemory::new(100);

    mem.store(b"key", b"value1", 5);
    mem.store(b"key", b"value2", 5);

    let recalled = mem.recall(b"key");
    assert!(recalled.is_some());
    assert_eq!(recalled.unwrap().as_slice(), b"value2");
}

#[test]
fn test_memory_multiple_keys() {
    let mem = AgentMemory::new(100);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);
    mem.store(b"key3", b"value3", 5);

    assert_eq!(mem.recall(b"key1").unwrap().as_slice(), b"value1");
    assert_eq!(mem.recall(b"key2").unwrap().as_slice(), b"value2");
    assert_eq!(mem.recall(b"key3").unwrap().as_slice(), b"value3");
}

#[test]
fn test_memory_isolation_between_agents() {
    let mem1 = AgentMemory::new(200);
    let mem2 = AgentMemory::new(201);

    mem1.store(b"shared_key", b"agent1_value", 5);
    mem2.store(b"shared_key", b"agent2_value", 5);

    // Each agent should see its own value
    assert_eq!(mem1.recall(b"shared_key").unwrap().as_slice(), b"agent1_value");
    assert_eq!(mem2.recall(b"shared_key").unwrap().as_slice(), b"agent2_value");
}

#[test]
fn test_memory_search_basic() {
    let mem = AgentMemory::new(300);

    mem.store(b"key1", b"hello world", 5);
    mem.store(b"key2", b"goodbye world", 5);
    mem.store(b"key3", b"hello there", 5);

    let results = mem.search(b"hello");
    assert_eq!(results.len(), 2);
}

#[test]
fn test_memory_search_no_results() {
    let mem = AgentMemory::new(300);

    mem.store(b"key1", b"hello", 5);
    mem.store(b"key2", b"world", 5);

    let results = mem.search(b"xyz");
    assert!(results.is_empty());
}

#[test]
fn test_memory_search_empty_query() {
    let mem = AgentMemory::new(300);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);

    // Empty query should match everything
    let results = mem.search(b"");
    assert_eq!(results.len(), 2);
}

#[test]
fn test_memory_search_isolation() {
    let mem1 = AgentMemory::new(400);
    let mem2 = AgentMemory::new(401);

    mem1.store(b"key", b"findme", 5);
    mem2.store(b"key", b"findme", 5);

    // Each agent should only find its own entries
    let results1 = mem1.search(b"findme");
    let results2 = mem2.search(b"findme");

    assert_eq!(results1.len(), 1);
    assert_eq!(results2.len(), 1);
    assert_eq!(results1[0].agent_id, 400);
    assert_eq!(results2[0].agent_id, 401);
}

#[test]
fn test_memory_recent() {
    let mem = AgentMemory::new(500);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);
    mem.store(b"key3", b"value3", 5);

    let recent = mem.recent(2);
    assert_eq!(recent.len(), 2);
    // Most recent should be first
    assert_eq!(recent[0].value.as_slice(), b"value3");
    assert_eq!(recent[1].value.as_slice(), b"value2");
}

#[test]
fn test_memory_recent_more_than_available() {
    let mem = AgentMemory::new(500);

    mem.store(b"key1", b"value1", 5);

    let recent = mem.recent(10);
    assert_eq!(recent.len(), 1);
}

#[test]
fn test_memory_recent_zero() {
    let mem = AgentMemory::new(500);

    mem.store(b"key1", b"value1", 5);
    mem.store(b"key2", b"value2", 5);

    let recent = mem.recent(0);
    assert!(recent.is_empty());
}

#[test]
fn test_memory_recent_isolation() {
    let mem1 = AgentMemory::new(600);
    let mem2 = AgentMemory::new(601);

    mem1.store(b"key1", b"value1", 5);
    mem2.store(b"key2", b"value2", 5);

    let recent1 = mem1.recent(10);
    let recent2 = mem2.recent(10);

    assert_eq!(recent1.len(), 1);
    assert_eq!(recent2.len(), 1);
    assert_eq!(recent1[0].agent_id, 600);
    assert_eq!(recent2[0].agent_id, 601);
}

#[test]
fn test_memory_importance_stored() {
    let mem = AgentMemory::new(700);

    mem.store(b"low", b"value", 1);
    mem.store(b"high", b"value", 10);

    let recent = mem.recent(2);
    // Check that importance is preserved
    let low_entry = recent.iter().find(|e| e.key[..3] == *b"low").unwrap();
    let high_entry = recent.iter().find(|e| e.key[..4] == *b"high").unwrap();

    assert_eq!(low_entry.importance, 1);
    assert_eq!(high_entry.importance, 10);
}

#[test]
fn test_memory_key_truncation() {
    let mem = AgentMemory::new(800);

    // Key longer than 64 bytes should be truncated
    let long_key = [b'x'; 100];
    mem.store(&long_key, b"value", 5);

    // Should be able to recall with truncated key
    let truncated_key = [b'x'; 64];
    let recalled = mem.recall(&truncated_key);
    assert!(recalled.is_some());
    assert_eq!(recalled.unwrap().as_slice(), b"value");
}

#[test]
fn test_memory_entry_timestamp() {
    let mem = AgentMemory::new(900);

    mem.store(b"key", b"value", 5);

    let recent = mem.recent(1);
    assert_eq!(recent.len(), 1);
    assert!(recent[0].timestamp > 0);
}

#[test]
fn test_memory_entry_clone() {
    let entry = MemoryEntry {
        key: [b'k'; 64],
        value: b"test_value".to_vec(),
        agent_id: 1,
        timestamp: 12345,
        importance: 7,
    };

    let cloned = entry.clone();
    assert_eq!(cloned.key, entry.key);
    assert_eq!(cloned.value, entry.value);
    assert_eq!(cloned.agent_id, entry.agent_id);
    assert_eq!(cloned.timestamp, entry.timestamp);
    assert_eq!(cloned.importance, entry.importance);
}

#[test]
fn test_memory_empty_value() {
    let mem = AgentMemory::new(1000);

    mem.store(b"key", b"", 5);

    let recalled = mem.recall(b"key");
    assert!(recalled.is_some());
    assert!(recalled.unwrap().is_empty());
}

#[test]
fn test_memory_large_value() {
    let mem = AgentMemory::new(1001);

    let large_value = [b'x'; 10000];
    mem.store(b"key", &large_value, 5);

    let recalled = mem.recall(b"key");
    assert!(recalled.is_some());
    assert_eq!(recalled.unwrap().len(), 10000);
}

#[test]
fn test_memory_max_entries_constant() {
    assert_eq!(MAX_ENTRIES, 1024);
}

#[test]
fn test_memory_binary_key() {
    let mem = AgentMemory::new(1100);

    let binary_key = b"\x00\x01\x02\x03";
    mem.store(binary_key, b"value", 5);

    let recalled = mem.recall(binary_key);
    assert!(recalled.is_some());
    assert_eq!(recalled.unwrap().as_slice(), b"value");
}

#[test]
fn test_memory_binary_value() {
    let mem = AgentMemory::new(1100);

    let binary_value = b"\x00\x01\x02\x03\xff\xfe";
    mem.store(b"key", binary_value, 5);

    let recalled = mem.recall(b"key");
    assert!(recalled.is_some());
    assert_eq!(recalled.unwrap().as_slice(), binary_value);
}

#[test]
fn test_memory_search_partial_match() {
    let mem = AgentMemory::new(1200);

    mem.store(b"key1", b"abcdefgh", 5);
    mem.store(b"key2", b"cdefghij", 5);
    mem.store(b"key3", b"efghijkl", 5);

    // "cdef" appears in key1 and key2
    let results = mem.search(b"cdef");
    assert_eq!(results.len(), 2);

    // "efgh" appears in all three
    let results = mem.search(b"efgh");
    assert_eq!(results.len(), 3);
}
