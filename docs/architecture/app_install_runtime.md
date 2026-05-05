# App install runtime

What runs while a user installs and launches a third-party app. This
overlaps with `capsule_install_flow.md` (which is the protocol-level
sequence) but focuses on the runtime behaviour: what is in memory,
what is on disk, what is on chain, what dies on reboot.

```
[install]   --MkSpawn-->   [running]
                              |
                              +-- crash       -->  [crashed]
                              |                       |
                              |                       +-- count<3   --> [respawn]
                              |                       |
                              |                       +-- count>=3  --> [disabled]
                              |
                              +-- update      -->  [respawn-with-new-version]
                              |
                              +-- uninstall   -->  [exit + endpoint revoke + wipe]
                              |
                              +-- exit clean  -->  [stopped]
```

## 1. Memory state during install

`capsule_installer` holds, in its own address space:

- the fetched package bytes (after hash verification)
- the decoded manifest
- the chosen artifact bytes
- a pending entitlement receipt (if a paid app)
- the user-approved capability mask

None of this leaks to other capsules. On install completion the
package bytes are dropped; the manifest and the receipt are handed
to `capsule_registry`.

## 2. RAM-only by default

The default install path stops at `MkSpawn`. The new app capsule is
in memory only; if the user reboots, the app and its state are gone.

The user has to choose persistence per app. Persistence requires:

- the manifest declares `storage_policy = persistent` or
  `encrypted_persistent`
- the user grants `CAP_PERSISTENCE`
- `capsule_registry` writes the verified package bytes to its own
  encrypted store, keyed by `capsule_id`
- on subsequent boot, init asks `capsule_registry` for the list of
  persistent installs and respawns them

Apps without `CAP_PERSISTENCE` cannot reach the persistent store
even indirectly. The persistence store is owned by
`capsule_registry`, not by the app.

## 3. App runtime caps

After spawn the app holds the cap mask the installer composed. The
kernel never broadens it. The user can revoke a cap at any time
through `capsule_settings`, which routes the change through
`capsule_installer`'s `RevokeCap` IPC. The kernel's `MkCapRevoke`
takes effect immediately; the next syscall the app issues fails
with `EPERM`.

## 4. Endpoint connections

The app declares the endpoints it intends to register and the
endpoints it intends to connect to. The compositor, the VFS, the
wallet, and any other system capsule check the caller's caps and
the connection grant before answering.

A connection grant is per (caller_pid, target_endpoint). Granting
`CAP_NETWORK` does not implicitly grant a connection to a specific
network capsule; the user (or the installer on the user's behalf)
authorises the connection.

## 5. Payment runtime

For paid apps:

- on install, `capsule_payment` issues an entitlement receipt and
  stores it in `capsule_registry`
- on launch, the runtime checks the receipt is still valid (not
  expired, not revoked); a stale receipt blocks launch and the
  user is prompted to renew
- for usage-metered apps, the app emits usage events to
  `capsule_payment`, which accumulates them and emits a receipt
  per epoch boundary
- settlement is async, in batches; an apparent payment failure on
  chain does not retroactively revoke a session that was running
  on a valid receipt

## 6. Update runtime

`capsule_update` polls the marketplace for new manifests on a
schedule the user controls (default: weekly). When a new version
is found:

1. fetch the new package
2. verify hashes and signatures
3. apply update policy:
   - `auto`: install in the background, restart the app on the
     next idle window
   - `prompt`: notify the user via the shell's status area
   - `manual`: do nothing, surface the new version in
     `capsule_market`

Atomic apply: spawn the new app capsule with the same caps the user
already approved, switch the registry's active pid to the new pid,
signal the old pid to exit. A failed spawn keeps the old pid
running.

## 7. Crash isolation

An app crash kills only the app pid. The kernel reaps the process,
the compositor releases its surfaces, the VFS closes its open
handles, and the registry marks the capsule `Dead`. The user sees
the window disappear; nothing else is affected.

Repeat crashes: `capsule_update` records a crash counter per
`capsule_id`. After three crashes inside one boot, automatic
restart is disabled until the user clicks "retry".

## 8. Uninstall runtime

`capsule_installer` performs:

1. signal the app pid to exit
2. release endpoint registrations through `MkCapRevoke`
3. drop the entry from `capsule_registry`
4. wipe the persistent store entry if the manifest declared
   persistence, and report a wipe proof to the user

After uninstall the `capsule_id` is gone from the system; a fresh
install starts from a clean state.
