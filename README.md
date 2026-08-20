# Quest 1 Bootloader Unlocker (WebUSB)

Downgrades the inactive boot slot of a Meta Quest 1 to firmware
`16476800119700000` (v29.0.0.66, 10 May 2021), boots it, and unlocks the
bootloader through CVE-2021-1931 — all from a browser tab.

Reimplements [darknight1050/quest-bootloader-unlocker][ref] for the single
build we downgrade to.

Stack: Vite + TypeScript, no framework.

```
npm install
npm run dev          # http://localhost:5173  (dev mode available)
npm run build        # typecheck + static bundle into dist/
npm run verify       # re-derive the unlock payload from the real firmware
npm run test-zip     # round-trip the backup archive through pack/unpack
npm run test-gpt     # GPT slot-attribute decoding, including the refuse-to-guess path
npm test             # all three
npm run hash-assets  # re-pin binaries/EXPECTED.sha256 after changing a payload
npm run pin-pe-hash  # re-pin the extracted bootloader hash in flow.ts
```

[ref]: https://github.com/darknight1050/quest-bootloader-unlocker

## The procedure

| # | Step | Needs |
| --- | --- | --- |
| 1 | Identify the device, gate on model and build | adb |
| 2 | Unpack the firmware, extract and patch the bootloader | — |
| 3 | Read the boot slots | adb |
| 4 | Get root via ionstack | adb, **typed confirmation** |
| 5 | Back up all 13 partitions the flash step overwrites, into OPFS | root |
| 6 | Re-read every backup and re-hash it against the device | root |
| 7 | Write the 13 downgrade images, verifying each | root, **typed confirmation** |
| 8 | Point bootctl at the downgraded slot | root, **typed confirmation**, offers revert |
| 9 | Reboot into fastboot | adb |
| 10 | Check build number, send the payload, request the unlock token | fastboot, **typed confirmation** |
| 11 | Re-confirm unlock state, then `set_active` the original slot | fastboot |

The backup covers exactly the partitions the flash step overwrites — the 13 in
the archive, no more and no less. Nothing is ever skipped: `checkPartitions`
aborts if any of them is missing on the target slot, the step refuses to start
unless the whole set fits in both browser storage and `/data/local/tmp`, and the
flash step refuses to run unless the backup holds all 13.

Every partition write is bracketed by hashes: the pushed file is hashed on the
device before `dd`, and the partition is hashed after. A mismatch aborts before
the next partition is touched.

`boot.img` is the second largest at 30,248,960 bytes (28.8 MiB); `modem.img` is
the largest at 30.9 MiB. The partitions they are written to are read at runtime
with `blockdev --getsize64` and are at least that size.

### A/B slot flags

`setActiveBootSlot` follows the normal A/B contract: it raises the slot's
priority, sets a retry counter, and marks the slot **not successful**. The
bootloader spends one retry per boot attempt and falls back to the other slot
when they run out; `markBootSuccessful()` — called by `update_verifier` once
Android is up — is what sets the successful flag and stops the countdown. So
"bootable, not yet successful" is the expected state after step 8, and it is
precisely what makes the fallback to the untouched slot work.

Two consequences worth knowing:

- **`getCurrentSlot()` cannot verify the switch.** It reports the slot the
  device is *running from*, and boot_control 1.0 has no `getActiveBootSlot`, so
  the HAL cannot answer "which slot boots next". Instead the active slot is read
  from the **GPT partition attributes** (`src/lib/gpt.ts`), where Qualcomm's
  boot_control actually stores it: bits 48-49 priority, 50 active, 51-53 retries,
  54 successful, 55 unbootable. The step refuses to reboot if the GPT names a
  different slot than the one requested.

  That bit layout is asserted rather than assumed: the decoded successful and
  unbootable bits are cross-checked against the HAL, and the active bit is only
  believed when they agree. If they do not, the tool says so and falls back to
  the flag-based check instead of reporting a confident guess. `npm run test-gpt`
  covers both cases.
- **`fastboot set_active` clears the flag too.** After the final step the
  original slot has a retry counter as well, so let the headset boot fully into
  the system once — Android sets the flag again. Until then the bootloader can
  still fall back.

### Confirming the unlock

The unlock step runs in a fixed order, and the order matters:

1. send the overflow payload
2. `flash:unlock_token`
3. read the lock state — **tentative**
4. `reboot-bootloader`, wait for re-enumeration, reconnect
5. read the lock state again — **authoritative**

Steps 1 and 2 must not be separated. The patch lives in the running
bootloader's memory, so rebooting between them would discard it before the
token is ever requested.

Step 3 is reported but not trusted: it comes from a bootloader whose signature
verification was just disabled in memory, so it says little about what was
persisted. Step 5 asks a bootloader that booted normally, and that answer is the
one the step succeeds or fails on. A bootloader that claims unlocked while
patched but locked after a clean boot is reported as exactly that.

The reboot also leaves the device ready to retry: the overflow does not always
land, and retrying against a bootloader whose command buffer was just overrun is
not meaningful.

`reboot-bootloader`, not `reboot-fastboot`: the latter enters *fastbootd*, which
runs from userspace and never executes the vulnerable `abl` path.

A manual **Reboot bootloader** button is also available on every fastboot step,
including in dev mode.

### Gates

- **Not a Quest 1** → abort. The images and the bootloader patch are specific to
  `monterey`.
- **Already at or below `16476800119700000`** → abort, reported as "already
  downgraded". Ordering uses a numeric comparison on
  `ro.build.version.incremental`, which was verified to match build-date order
  across all 55 archived Quest 1 builds.
- **Build not in `rootSupported`** → warn only; ionstack may simply fail.

### Typed confirmations

The dangerous steps open a dialog whose phrase is built from live device state
— `overwrite _b`, `boot _b`, `unlock 16476800119700000` — so it cannot be
guessed without reading the dialog. The "switch the active slot" dialog also
carries a **Revert slot to backup** button, which is the last point where
rolling back is purely local.

## Payload integrity

Everything pushed to the headset or written to a partition is hash-checked at
two levels.

**Build time.** `scripts/sync-assets.mjs` refuses to publish anything to
`public/` unless it matches `binaries/EXPECTED.sha256`, which is checked in. A
payload cannot change without someone running `npm run hash-assets` on purpose.

**Run time.** Those hashes are written to `src/data/asset-hashes.json`, which is
**bundled into the JavaScript**, not fetched. Every payload is hashed after
download and compared against it, and a URL that is not in the manifest is
refused outright rather than loaded unverified. Because the manifest ships
inside the bundle, replacing a file in `public/binaries` — or on the wire —
cannot be paired with replacing its expected hash.

On top of that the archive's `abl.img` and the extracted LinuxLoader image are
pinned separately (`EXPECTED_ABL_SHA256`, `EXPECTED_PE_PREFIX_SHA256`), so a
repacked archive cannot slip a different bootloader past the patch-site check.

What this does **not** protect against: a compromised checkout. If someone can
edit the bundle they can edit the hashes with it. Serve over `https` or
`localhost` — on a plain-HTTP deployment the bundled hashes are the only thing
standing between a network attacker and a flashed payload, and the page warns
when it is not on a secure origin.

## Dev mode

Only available when Vite is serving locally: `import.meta.env.DEV` gates it, the
toggle is removed from a production build, `?dev=1` is ignored there, `Flow`
throws if constructed in dev mode, and `sync-assets` leaves the dev payloads out
of `dist` entirely.

`binaries/dev/` is gitignored, so a fresh clone will not have it. That is not an
error: `sync-assets` warns and carries on, the core flow is unaffected, and only
dev mode for that device is unavailable. The hash stays pinned in
`binaries/EXPECTED.sha256` and in the bundled manifest either way, so a payload
someone does supply is still checked against the expected one.

It exists to exercise the parts that do not need a Quest 1 — ionstack, the
backup round-trip, and the fastboot lock-state read — on other hardware:

| # | Step | What it does |
| --- | --- | --- |
| 1 | Identify | Picks the ionstack build from `ro.product.device` |
| 2 | Get root | Runs that build with its own tuning, checks `id` in a fresh shell |
| 3 | Enumerate partitions | Resolves the by-name directory, lists the inactive slot |
| 4 | Back up | Round-trips every partition under the size cap through OPFS |
| 5 | Re-verify | Re-reads them from storage and re-hashes against the device |
| 6 | Reboot into fastboot | `adb reboot bootloader`, then re-grant USB access |
| 7 | Read lock state | Parses `getvar:unlocked` and `oem device-info` |

Step 6 is reversible and writes nothing — fastboot is only a boot mode, and
`fastboot reboot` (or holding the power button) returns to Android. It exists so
the reconnect-over-fastboot path, which is where the real flow is most likely to
trip on Windows driver binding, gets exercised too.

The size cap (default 256 MiB, adjustable in the dev banner) exists to keep a
multi-gigabyte `super` out of browser storage — not to keep the rehearsal small.
The real Quest 1 backup pulls a ~31 MiB `modem` and a ~29 MiB `boot`, so a cap
that excluded a Quest 3's ~96 MiB `boot_b`/`vendor_boot_b` and ~100 MiB
`recovery_b` would only ever exercise short transfers. Anything skipped is
logged by name and size, and the step refuses to start if the selection will not
fit in the available storage quota.

Profiles live in `src/data/profiles.ts`. The Quest 1 build sprays memfd over one
PFN range; the Quest 3 build sprays io_uring over two and holds the primitive
for 300 s (`IONSTACK_KEEPER_HOLD_SEC`). They are not interchangeable, so the
binary and its environment travel together and an unknown codename is refused
rather than guessed at.

Dev mode never writes a partition, never switches a slot and never unlocks
anything — it is a separate step list, so those paths are not reachable rather
than merely disabled. It also will not reboot the device into fastboot for you.

## Recovery

The **Restore a backup** panel is an independent path (`src/lib/restore.ts`):
connect the headset, and it pushes ionstack, roots the device, resolves the
by-name directory and writes the images back. No downgrade, no fastboot, no
unlock. The panel is always visible, so the recovery path is there on a fresh
profile too.

### What it can and cannot recover

Restoring needs a working adb shell, because ionstack has to run on the device.
That bounds it precisely:

- **Inactive slot flashed badly, still booted on the good slot** — the main
  case, and what the revert button in the "switch the active slot" dialog does.
- **Switched slots and the downgrade booted** — restore the other slot from the
  running one.
- **Switched slots and the new one does not boot** — the bootloader falls back
  to the untouched slot after failed attempts; once you are booted again, the
  backup can repair the bad slot.
- **Nothing boots at all** — the backup cannot help. There is no shell, so
  ionstack cannot run. Nothing in this tool recovers from that.

The real safety net is therefore *the slot this tool never touches*, not the
backup. The backup is what lets you undo the slot it does touch.

Each image is re-hashed out of storage before it is written and the partition is
hashed after, so a restore cannot silently half-succeed.

**Save as zip** writes the whole set — every partition image plus its
`backup.json` — into a single archive, streamed straight to the file you pick so
a few hundred megabytes never has to sit in a tab's memory.

**Import backup from disk** is its inverse, and the way back if the browser
profile that took the backup is gone. It accepts that zip, or loose `.img`
files. When the archive carries its original `backup.json`, every image is
checked against the hash recorded in it: anything that does not match is
rejected rather than imported, and the set is marked complete only if all of
them survive.

### Deleting

When the unlock finishes, the tool offers to delete the backup there and then —
with the consequence stated: the downgraded slot still holds
`16476800119700000`, and the backup is the only thing that puts it back. Choosing
to delete still goes through the normal typed confirmation, because that is the
moment someone is most likely to click through on autopilot.

Each set also has a **Delete** button. How hard it asks depends on what is being
thrown away: a dev rehearsal or a half-finished set is routine cleanup and gets
a plain confirm, while a complete backup takes a typed phrase — and says so
explicitly when it is the last complete backup stored for that headset, since
deleting it removes the only way to undo a downgrade of that slot. There is no
undo; save the zip first if you are unsure.

### Completeness

Backup sets record the partitions they were meant to hold and are marked
`complete` only once every one of them is stored. A set that stopped part-way, a
dev-mode rehearsal subset, or a partial import is labelled in the list, warned
about in the restore dialog, and can never be mistaken for a full device backup.

Backups live in the origin private file system under `backups/<serial>-<time>/`,
with a `backup.json` manifest. `navigator.storage.persist()` is requested before
the first write. **Clearing site data destroys them** — use "Save to disk" for a
copy that outlives the browser profile.

## How the unlock is built

`abl.img` from the downgrade archive is an ARM ELF32 whose loadable segment is a
UEFI firmware volume:

```
abl.img  ELF32 (EM_ARM)
  └── PT_LOAD @0x3000, 0x40000 bytes, loaded at 0x9fa00000
        └── firmware volume (EFI_FIRMWARE_FILE_SYSTEM2_GUID)
              └── FFS file type 0x0b
                    └── GUID_DEFINED section, LZMA_CUSTOM_DECOMPRESS
                          └── inner firmware volume
                                └── "LinuxLoader", FFS type 0x09
                                      └── PE32 section — 0x9a000 bytes
```

At offset `0x3777c` that image holds `c9 04 00 54` (`b.ls +0x98`), the branch
past the signature-verification failure path. Patching it to `b6 00 00 14`
(`b +0x2d8`) makes the jump unconditional. The payload sent to the bootloader is
`0x100000` filler bytes of `0x0c` followed by the patched image truncated to
`0x37780`, overrunning the fastboot command buffer so the patched copy lands
where it will execute.

`npm run verify` re-derives all of this from the real archive and asserts the
extracted PE's sha256, the pre-patch bytes, the payload length and layout, and
that a wrong build is rejected.

## Requirements

- Chromium browser (Chrome, Edge, Opera) — Firefox and Safari have no WebUSB.
- Secure context: `localhost` or `https`.
- Developer Mode on; accept the RSA prompt in VR on first connect.
- `adb kill-server`, and close SideQuest — nothing else may hold the interface.
- **Windows:** both the ADB *and* the fastboot interfaces must be bound to
  WinUSB via [Zadig](https://zadig.akeo.ie/). They are separate USB devices with
  separate permissions, so the fastboot device needs its own picker grant.
- ~70 MB free in `/data/local/tmp` and ~70 MB of browser storage quota.

## Layout

```
binaries/           firmware archive + ionstack + bootctl_shim (mirrored into public/)
binaries/dev/       dev-only payloads — gitignored, absent from a fresh clone
native/             bootctl_shim.c and its trimmed AOSP headers
scripts/verify-abl  payload derivation checked against the real firmware
src/data/           versions.json, generated from the firmware archive manifest
src/lib/abl         UEFI parsing, PE extraction, patch, payload
src/lib/bootctl     slot control via bootctl_shim
src/lib/device      shell, props, push/pull, gates
src/lib/fastboot    fastboot over WebUSB, unlock, unlock-state readback
src/lib/flow        the step machine
src/lib/partitions  backup, flash, verify, restore
src/lib/restore     standalone recovery path
src/lib/root        ionstack
src/lib/storage     OPFS backup sets
src/vendor/lzma-d   vendored LZMA-JS decoder (MIT)
```

## Risk

Unlocking makes the headset wipe user data on its next boot. A partition write
interrupted part-way through `xbl` or `abl` leaves a slot that will not boot,
and there is no supported un-brick path for a Quest 1 whose bootloader chain is
damaged.

Keeping the other slot intact is the safety net that matters — the backup only
helps while the device still boots something, because restoring it requires an
adb shell. If both slots are gone, so are you.

## Licence

MIT — see [LICENSE](LICENSE).

That covers the source here. It does not cover what lives under `binaries/`:
the firmware images are Meta's, and the ionstack builds belong to their author.
`bootctl_shim` is built from `native/bootctl_shim.c` and is MIT with the rest.
`src/vendor/lzma-d.js` is LZMA-JS by Nathan Rugg, MIT, with its notice intact.
