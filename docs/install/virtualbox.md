# NONOS VirtualBox Setup

Run NONOS in VirtualBox.

## Quick Start

```
chmod +x setup-nonos-vm.sh
./setup-nonos-vm.sh
VBoxManage startvm NONOS
```

## What the Script Does

1. Downloads the NONOS disk image from nonos.software
2. Converts it to VDI format (VirtualBox native)
3. Creates a VM with correct settings
4. Attaches the disk and configures boot

## Why Not Use the ISO?

VirtualBox EFI has issues booting custom ISOs. The IMG file works because it's a raw disk image with a proper GPT partition table and EFI System Partition.

## VM Settings

Taken from the NONOS Makefile QEMU configuration:

| Setting | Value | Why |
|---------|-------|-----|
| Chipset | ICH9 | Q35 equivalent, modern chipset |
| Firmware | EFI64 | NONOS is UEFI only |
| RAM | 1GB | Matches Makefile |
| CPU | 2 cores, host profile | Exposes real CPU features |
| Graphics | VBoxSVGA | Closest to QEMU vga std |
| Storage | AHCI | Modern SATA controller |
| Network | Intel e1000 | Same as Makefile |

## Network

If you have WiFi, the script bridges to it automatically. Otherwise falls back to NAT.

Bridged = VM gets real IP on your network
NAT = VM shares host IP, outbound only

## Troubleshooting

**VM won't start / locked session**
```
pkill -9 VirtualBoxVM
VBoxManage startvm NONOS
```

**Boot failure**
Make sure you're using the IMG file, not ISO. The script handles this.

**No network**
Check your WiFi interface name:
```
VBoxManage list bridgedifs
```
Edit the script if yours is different from "Wi-Fi".

## Files

```
setup-nonos-vm.sh    - setup script
nonos.img            - downloaded disk image
nonos.vdi            - converted for vbox
```

## Manual Setup

If you want to do it yourself in the GUI:

1. New VM → Type: Other, Version: Other/Unknown (64-bit)
2. System → Chipset: ICH9, Enable EFI
3. System → Processor: 2 CPUs
4. Display → Graphics: VBoxSVGA, 128MB
5. Storage → Add SATA controller, attach the VDI
6. Network → Bridged Adapter, Intel PRO/1000 MT Server

## Requirements

- VirtualBox 6.1+
- curl (for download)
- ~500MB disk space
