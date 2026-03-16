# Driver Module Tests

## Location

`src/drivers/*/tests.rs` and `src/drivers/*/tests/`

## Coverage

### PCI (89 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Device enumeration | 24 | `src/drivers/pci/tests/` |
| Config space | 18 | `src/drivers/pci/tests/address.rs` |
| BAR allocation | 22 | `src/drivers/pci/tests/bar.rs` |
| Capabilities | 15 | `src/drivers/pci/tests/types.rs` |
| Error handling | 10 | `src/drivers/pci/tests/errors.rs` |

### USB/xHCI (156 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Ring operations | 34 | `src/drivers/xhci/tests/trb.rs` |
| TRB handling | 28 | `src/drivers/xhci/trb/tests.rs` |
| Device contexts | 24 | `src/drivers/xhci/tests/context.rs` |
| Endpoint | 22 | `src/drivers/xhci/tests/types_tests.rs` |
| Constants | 18 | `src/drivers/xhci/tests/constants_tests.rs` |
| DMA | 16 | `src/drivers/xhci/dma.rs` |
| Error types | 14 | `src/drivers/xhci/tests/error.rs` |

### AHCI/SATA (78 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Port handling | 28 | `src/drivers/ahci/tests.rs` |
| Command list | 22 | `src/drivers/ahci/command/tests.rs` |
| FIS structures | 18 | `src/drivers/ahci/fis/tests.rs` |
| Capabilities | 10 | `src/drivers/ahci/cap/tests.rs` |

### NVMe (94 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Queue handling | 32 | `src/drivers/nvme/queue/tests.rs` |
| Commands | 28 | `src/drivers/nvme/cmd/tests.rs` |
| Namespace | 18 | `src/drivers/nvme/ns/tests.rs` |
| Admin commands | 16 | `src/drivers/nvme/admin/tests.rs` |

### Network/RTL8139 (43 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Packet TX/RX | 18 | `src/drivers/rtl8139/tests.rs` |
| Ring buffers | 15 | `src/drivers/rtl8139/ring/tests.rs` |
| Constants | 10 | `src/drivers/rtl8139/constants.rs` |

### WiFi (67 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| 802.11 frames | 24 | `src/drivers/wifi/tests.rs` |
| Authentication | 18 | `src/drivers/wifi/auth/tests.rs` |
| Encryption | 15 | `src/drivers/wifi/crypto/tests.rs` |
| Scanning | 10 | `src/drivers/wifi/scan/tests.rs` |

### Audio (52 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| HDA codec | 22 | `src/drivers/audio/hda/tests.rs` |
| PCM streams | 18 | `src/drivers/audio/pcm/tests.rs` |
| Mixer | 12 | `src/drivers/audio/mixer/tests.rs` |

### VirtIO (64 tests)

| Component | Tests | Source |
|-----------|-------|--------|
| Queue operations | 24 | `src/drivers/virtio/queue/tests.rs` |
| Block device | 18 | `src/drivers/virtio/block/tests.rs` |
| Network | 14 | `src/drivers/virtio/net/tests.rs` |
| Config | 8 | `src/drivers/virtio/config/tests.rs` |

## Running

```bash
cargo test --lib --features std drivers::
```
