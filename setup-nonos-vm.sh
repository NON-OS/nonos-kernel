#!/bin/bash
#
# setup NONOS in virtualbox
# uses IMG file (not ISO) because vbox EFI is garbage with ISOs
# settings taken from Makefile qemu config
#

set -e

VM="NONOS"
IMG_URL="https://nonos.software/iso/nonos-0.8.2-alpha.img"
DIR="$(cd "$(dirname "$0")" && pwd)"

### check vbox ###

command -v VBoxManage >/dev/null || { echo "install virtualbox first"; exit 1; }

### get the disk image ###

if [ ! -f "$DIR/nonos.img" ]; then
    echo "downloading nonos disk image..."
    curl -L -o "$DIR/nonos.img" "$IMG_URL" --progress-bar
fi

if [ ! -f "$DIR/nonos.vdi" ]; then
    echo "converting to vdi..."
    VBoxManage convertfromraw "$DIR/nonos.img" "$DIR/nonos.vdi" --format VDI
fi

### kill old vm if exists ###

if VBoxManage showvminfo "$VM" &>/dev/null; then
    echo "removing old $VM vm..."
    VBoxManage controlvm "$VM" poweroff 2>/dev/null || true
    sleep 2
    VBoxManage unregistervm "$VM" --delete 2>/dev/null || true
fi

### create vm ###

echo "creating vm..."
VBoxManage createvm --name "$VM" --ostype Other_64 --register

# ich9 = q35 equivalent, required for nonos
VBoxManage modifyvm "$VM" --chipset ich9

# efi boot, nonos doesnt do legacy bios
VBoxManage modifyvm "$VM" --firmware efi64

# 1G ram like makefile says
VBoxManage modifyvm "$VM" --memory 1024 --cpus 2

# cpu stuff
VBoxManage modifyvm "$VM" --pae off --longmode on --cpu-profile host
VBoxManage modifyvm "$VM" --hwvirtex on --nestedpaging on --largepages on
VBoxManage modifyvm "$VM" --vtx-vpid on --vtx-ux on
VBoxManage modifyvm "$VM" --apic on --x2apic on --ioapic on --hpet on

# graphics, vga std = vboxsvga
VBoxManage modifyvm "$VM" --vram 128 --graphicscontroller vboxsvga

# storage - ahci like modern systems
VBoxManage storagectl "$VM" --name SATA --add sata --controller IntelAhci

# copy vdi to vm folder and attach
mkdir -p "$HOME/VirtualBox VMs/$VM"
cp "$DIR/nonos.vdi" "$HOME/VirtualBox VMs/$VM/boot.vdi"
VBoxManage storageattach "$VM" --storagectl SATA --port 0 --device 0 --type hdd \
    --medium "$HOME/VirtualBox VMs/$VM/boot.vdi"

# boot from disk
VBoxManage modifyvm "$VM" --boot1 disk --boot2 none --boot3 none --boot4 none

# network - e1000 like makefile, bridged to wifi if possible
WIFI=$(VBoxManage list bridgedifs 2>/dev/null | grep "^Name:" | grep -i wi-fi | head -1 | cut -d: -f2- | xargs)
if [ -n "$WIFI" ]; then
    VBoxManage modifyvm "$VM" --nic1 bridged --bridgeadapter1 "$WIFI" --nictype1 82545EM
else
    VBoxManage modifyvm "$VM" --nic1 nat --nictype1 82545EM
fi

# usb
VBoxManage modifyvm "$VM" --usb on --usbehci on --usbxhci on

# audio
case "$(uname)" in
    Darwin) VBoxManage modifyvm "$VM" --audio-driver coreaudio ;;
    Linux)  VBoxManage modifyvm "$VM" --audio-driver pulse ;;
esac
VBoxManage modifyvm "$VM" --audioout on

echo ""
echo "done. run with:"
echo "  VBoxManage startvm $VM"
echo ""
