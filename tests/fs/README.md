# Filesystem Module Tests

## Location

`src/fs/*/tests.rs`

## Coverage (54 tests)

### File Descriptors

- FD allocation/deallocation
- FD table management
- Duplicate handling
- Close semantics

Source: `src/fs/fd/tests.rs`

### VFS Operations

- open/close
- read/write
- seek
- stat

Source: `src/fs/vfs/tests.rs`

### Path Resolution

- Absolute paths
- Relative paths
- Symlink following
- Mount points

Source: `src/fs/path/tests.rs`

### Cache

- Inode cache
- Dentry cache
- Buffer cache
- Invalidation

Source: `src/fs/cache/tests.rs`

## Running

```bash
cargo test --lib --features std fs::
```
