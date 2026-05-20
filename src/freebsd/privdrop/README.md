# FreeBSD::Privdrop

Privilege-drop helpers for Crystal on FreeBSD: `setuid`, `setgid`,
`setgroups`, `initgroups`, `chroot`, and environment scrubbing — with correct
ordering documentation and Crystal error handling.

```crystal
require "freebsd/privdrop"
```

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises
> `FreeBSD::Privdrop::UnsupportedPlatformError`.

## Quick start

```crystal
require "freebsd/privdrop"
require "freebsd/capsicum"

# 1. Open everything you'll need after sandboxing.
log = File.open("/var/log/app.log", "a")

# 2. Drop privileges in one call (see ordering rules below).
FreeBSD::Privdrop.drop(
  uid: 65534_u32,   # nobody
  gid: 65534_u32,
  chroot: "/var/empty",
  scrub_env: true,
)

# 3. Enter capability mode — root is already gone.
FreeBSD::Capsicum.sandbox!

log.puts "running as nobody inside /var/empty, in capability mode"
```

## Safe ordering — mandatory

Steps must happen in this exact order. Doing them out of order silently
produces an insecure or broken process.

| Step | Call | Notes |
|------|------|-------|
| 1 | Open FDs, Casper services | Must happen before any restriction |
| 2 | `init_groups` / `setgroups` / `clear_groups` | Reads `/etc/group` — before chroot |
| 3 | `FreeBSD::Privdrop.chroot(path)` | Optional; root required |
| 4 | `FreeBSD::Privdrop.setgid(gid)` | Root required; must precede setuid |
| 5 | `FreeBSD::Privdrop.setuid(uid)` | Root permanently relinquished here |
| 6 | `FreeBSD::Privdrop::Env.scrub` | After uid drop |
| 7 | `FreeBSD::Capsicum.sandbox!` | Locks the process into cap mode |

`FreeBSD::Privdrop.drop` executes steps 2–6 in this order automatically.

## chroot

```crystal
FreeBSD::Privdrop.chroot("/var/empty")
# After this call the working directory is "/" inside the new root.
```

Must be called as root. The working directory is moved to `"/"` inside the
new root automatically after a successful `chroot(2)`.

## Supplementary groups

Three options — choose one before `setgid`:

```crystal
# Option A: build from /etc/group (must happen before chroot)
FreeBSD::Privdrop.init_groups("www", gid)

# Option B: explicit list
FreeBSD::Privdrop.setgroups([1000_u32, 1001_u32])

# Option C: clear all supplementary groups
FreeBSD::Privdrop.clear_groups
```

> **Caveat:** `init_groups` calls `initgroups(3)`, which reads `/etc/group`
> at call time. If you are also using `chroot`, call `init_groups` **before**
> `chroot` — unless the new root contains a valid `/etc/group`. When in doubt,
> resolve the gid list yourself and use `setgroups([...])` explicitly.

## setgid and setuid

```crystal
FreeBSD::Privdrop.setgid(65534_u32)   # set group first
FreeBSD::Privdrop.setuid(65534_u32)   # set user last — root gone after this
```

`setgid` must precede `setuid`. Once `setuid` returns with a non-zero uid the
process can no longer call `setgid` or any other root-only syscall.

## Convenience `drop`

```crystal
FreeBSD::Privdrop.drop(
  uid: 65534_u32,
  gid: 65534_u32,
  username: "www",      # optional: call initgroups before chroot
  chroot: "/var/www",   # optional
  scrub_env: true,      # default
)
```

Executes all steps in the safe order. `username:` triggers `init_groups`;
omitting it calls `clear_groups` instead. `chroot:` is optional.

## Environment scrubbing

```crystal
removed = FreeBSD::Privdrop::Env.scrub
# => ["LD_PRELOAD", ...]  — names of vars that were actually set
```

`Env.scrub` removes the following variables if present and resets `PATH` to
`"/usr/bin:/bin"`:

- `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_LIBMAP`, `LD_DEBUG`,
  `LD_ELF_HINTS_PATH`
- `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`
- `IFS`, `CDPATH`, `ENV`, `BASH_ENV`

Individual helpers:

```crystal
FreeBSD::Privdrop::Env.delete("MY_VAR")   # => true if it existed
FreeBSD::Privdrop::Env.reset_path          # resets PATH, returns old value
```

## Step-by-step example

```crystal
require "freebsd/privdrop"
require "freebsd/capsicum"

# Step 1 — acquire resources while still root
casper_channel = FreeBSD::Casper::Channel.open
dns            = casper_channel.dns
log            = File.open("/var/log/app.log", "a")

# Step 2 — supplementary groups (reads /etc/group before chroot)
FreeBSD::Privdrop.init_groups("www", 65534_u32)

# Step 3 — chroot (optional)
FreeBSD::Privdrop.chroot("/var/www")

# Steps 4 & 5 — drop to www:www
FreeBSD::Privdrop.setgid(65534_u32)
FreeBSD::Privdrop.setuid(65534_u32)

# Step 6 — environment
FreeBSD::Privdrop::Env.scrub

# Step 7 — capability mode
FreeBSD::Capsicum.sandbox!
```
