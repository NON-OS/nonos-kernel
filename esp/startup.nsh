echo NONOS startup.nsh launching...
for %p in 0 1 2 3 4 5
  if exist fs%p:\EFI\BOOT\BOOTX64.EFI then
    fs%p:
    \EFI\BOOT\BOOTX64.EFI
    exit
  endif
endfor
echo NONOS: BOOTX64.EFI not found on any fs*
