# Default capsules

The capsules the OS ships with. Every one is a signed userland
capsule, runs in its own address space, and uses caps the user
implicitly grants by accepting the default install. Anything outside
this list is an opt-in install through `capsule_market`.

```
   capsule_entropy
        |
        v
   capsule_keyring
        |
   +----+--------+--------+
   v             v        v
 capsule_      capsule_  capsule_
 crypto        ramfs     vfs
                    \      /
                     \    /
                      v  v
                  (file-using apps)

   capsule_input  --+
                    |
   capsule_display -+--> capsule_compositor --> capsule_shell
                                                     |
                                                     v
                                               app capsules
                                                  market
                                                  wallet
                                                  terminal
                                                  filemanager
                                                  browser
                                                  settings
```

## 1. System capsules

Installed by `init` at boot. The user does not opt out; without these
the OS is not usable.

| Capsule | Role | Required caps |
|---|---|---|
| `capsule_entropy` | RNG broker | `CAP_ENTROPY` |
| `capsule_keyring` | publisher key custody | `CAP_CRYPTO` |
| `capsule_ramfs` | RAM-only filesystem | `CAP_VFS` |
| `capsule_vfs` | unified filesystem broker | `CAP_VFS` |
| `capsule_crypto` | hash, KDF, AEAD, signing service | `CAP_CRYPTO`, `CAP_ENTROPY` |
| `capsule_input` | input event distribution | `CAP_INPUT` |
| `capsule_display` | framebuffer custody | `CAP_DISPLAY` |
| `capsule_compositor` | surfaces, z-order, damage | `CAP_DISPLAY`, `CAP_INPUT` |
| `capsule_shell` | desktop shell | `CAP_DISPLAY`, `CAP_INPUT` |
| `capsule_wallpaper` | wallpaper surface | `CAP_DISPLAY` |
| `capsule_market` | marketplace UI | `CAP_DISPLAY`, `CAP_INPUT`, `CAP_NETWORK` |
| `capsule_installer` | install pipeline | `CAP_VFS`, `CAP_CRYPTO`, `CAP_NETWORK` |
| `capsule_payment` | NOX payment runtime | `CAP_NETWORK`, `CAP_WALLET_SPEND` |
| `capsule_wallet` | wallet identity and signing | `CAP_CRYPTO`, `CAP_WALLET_VIEW` |
| `capsule_registry` | local install registry | `CAP_VFS` |
| `capsule_update` | update resolver | `CAP_VFS`, `CAP_CRYPTO`, `CAP_NETWORK` |

## 2. Default user-facing capsules

Pre-bundled but user can uninstall. Free, signed by the NØNOS
publisher key.

| Capsule | Purpose |
|---|---|
| `capsule_settings` | desktop settings |
| `capsule_terminal` | terminal frontend |
| `capsule_filemanager` | VFS file manager |
| `capsule_browser` | browser shell |
| `capsule_text_editor` | text viewer and editor |
| `capsule_system_monitor` | process and resource view |
| `capsule_package_ui` | install / uninstall / update UI |

These ship as part of the kernel image-adjacent capsule bundle so a
fresh install boots into a working desktop without network access.
After first boot, updates flow through `capsule_market`.

## 3. Manifests at rest

Each default capsule has a manifest under `userland/<name>/manifest`.
The build system signs the manifest with the NØNOS publisher key
during release. The bundle layout matches `capsule_package.schema.json`.

## 4. Capability defaults

The default capsules list their `required_caps` and `optional_caps`
the same way third-party capsules do. `capsule_browser` requires
`CAP_NETWORK` and `CAP_DISPLAY`; the user can revoke `CAP_NETWORK`
at the cost of breaking the browser. There is no special
"system capsule" privilege; the kernel treats default and
third-party capsules identically.

## 5. Free vs. paid

Default capsules are free. The marketplace can list paid
third-party capsules under any of the payment modes documented in
`nox_payment_runtime.md`. The boot graph never depends on a paid
capsule.

## 6. Replace and remove

A user can replace a default capsule with a third-party
implementation by:

1. Installing the replacement through `capsule_market`.
2. Pointing `capsule_settings` at the new capsule's endpoint name.
3. Removing the old capsule.

The endpoint indirection means the rest of the system does not
care which `capsule_terminal` is bound; it talks to whatever is
registered as `terminal.frontend`.
