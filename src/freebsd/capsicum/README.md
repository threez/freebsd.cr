# FreeBSD::Capsicum

Crystal bindings for **[Capsicum]** — FreeBSD's in-kernel capability mode,
fd rights, and process descriptors.

[Capsicum]: https://www.cl.cam.ac.uk/research/security/capsicum/

```crystal
require "freebsd/capsicum"
```

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises
> `FreeBSD::Capsicum::UnsupportedPlatformError`.

## Crystal and forking

Crystal removed `Process.fork` from its public API because `fork(2)` is
unsafe in a multi-threaded process: only the calling thread survives into the
child, while the other threads vanish — leaving the child holding their
mutexes, heap state, and file descriptors. Crystal's GC, scheduler, and
channel infrastructure rely on shared mutable state that a naïve fork would
corrupt, making deadlocks near-certain.

`pdfork` side-steps this in two ways:

1. **Fork early, before any concurrent fibers are started.** At that point
   there is only one thread, so there is nothing to corrupt.
2. **Reinitialize the runtime immediately in the child.** Every call site in
   this library — `FreeBSD::Capsicum.pdfork`, `FreeBSD::Casper::Helper.spawn`,
   and the spec helper `in_sandbox_child` — calls
   `Process.after_fork_child_callbacks` as its first act in the child. This
   rehooks the event loop, signal handlers, and RNG seeds, giving the child a
   clean, single-threaded Crystal runtime.

`spawn` (Crystal's green-thread primitive) cannot replace `pdfork` here
because it stays in-process. The whole point of `pdfork` for Capsicum is a
*separate process* that can be independently sandboxed — `cap_enter(2)` is
per-process; you cannot sandbox one fiber while leaving another unsandboxed.

**Practical rule:** call `pdfork` / `Helper.spawn` before starting any
concurrent fibers or thread pools, and let each child run its own fiber
scheduler freely from then on.

## Enter capability mode

```crystal
require "freebsd/capsicum"

FreeBSD::Capsicum.sandbox do
  # Capability mode is active. Global namespaces are gone:
  # File.open("/etc/passwd") here would raise (ECAPMODE).
  # Pre-opened FDs still work, subject to their rights.
end
```

`FreeBSD::Capsicum.sandbox!` enters capability mode without yielding — it is
one-way per process; once entered there is no going back.

`FreeBSD::Capsicum.sandboxed?` returns `true` when the current process is
already in capability mode.

## Restrict rights on a file descriptor

```crystal
require "freebsd/capsicum"

f = File.open("/var/log/app.log", "a")
FreeBSD::Capsicum::Capability::Rights
  .new(FreeBSD::Capsicum::Capability::Right::Write,
       FreeBSD::Capsicum::Capability::Right::Fsync,
       FreeBSD::Capsicum::Capability::Right::Fstat)
  .apply_to(f)

FreeBSD::Capsicum.sandbox!
f.puts "now we're confined"   # works — Write was retained
# f.read would fail — Read was not granted
```

`Rights.of(io)` returns the current effective rights on an fd:

```crystal
rights = FreeBSD::Capsicum::Capability::Rights.of(f)
rights.includes?(FreeBSD::Capsicum::Capability::Right::Write)  # => true
```

`Rights#clear(*rights)` removes individual rights from a set before applying
it. `Rights#add_raw(Enumerable(UInt64))` lets you add rights that are not yet
enumerated in `Right`.

## Limit ioctl commands

```crystal
# Allow only FIONREAD on the socket; forbid everything else.
FreeBSD::Capsicum::Capability.limit_ioctls(sock, [LibC::FIONREAD.to_u64])

# Forbid all ioctls.
FreeBSD::Capsicum::Capability.limit_ioctls(sock, [] of UInt64)
```

## Limit fcntl commands

```crystal
FreeBSD::Capsicum::Capability.limit_fcntls(
  f,
  FreeBSD::Capsicum::Capability::FcntlMask::GetFl |
  FreeBSD::Capsicum::Capability::FcntlMask::SetFl,
)
```

`FcntlMask` is a `@[Flags]` enum covering `GetFl`, `SetFl`, `GetOwn`,
`SetOwn` — pass any bitwise-OR combination.

## pdfork — fork a child you can still control from a sandbox

`pdfork(2)` forks a child and returns it as a *file descriptor* rather than a
PID. The descriptor stays valid after `cap_enter` (capability mode wipes the
PID namespace but not your fds), so the parent can `kill`/`wait`/`close` the
child from inside the sandbox.

```crystal
require "freebsd/capsicum"

pd = FreeBSD::Capsicum.pdfork do
  # Child: drop into the actual workload and sandbox.
  FreeBSD::Capsicum.sandbox!
  do_untrusted_work
  0   # exit code
end

# Parent: can sandbox itself and still manage the child via the pd.
FreeBSD::Capsicum.sandbox!

pd.pid                          # global PID (logging only — unusable in cap mode)
pd.current_pid                  # nil once the kernel has reaped the child
pd.kill(Signal::TERM)
status = pd.wait                # blocks via kqueue/EVFILT_PROCDESC; works in cap mode
status.try(&.exit_code)         # => Int32?, just like Process::Status
pd.wait(500.milliseconds)       # => nil on timeout (child still running)
pd.close                        # SIGKILL + reap (unless created with daemon: true)
```

`pdfork` options:
- `daemon: true` — the fd will NOT signal-kill the child on close (`PD_DAEMON`)
- `cloexec: true` — the fd is `O_CLOEXEC` (`PD_CLOEXEC`)

Exceptions raised inside the child block are caught and logged to stderr; the
child exits with status 1 rather than escaping.

> **Note:** `pd.wait` uses `kqueue` + `EVFILT_PROCDESC`/`NOTE_EXIT` and
> cooperatively yields the OS thread via `Fiber.syscall`, so other fibers
> continue to run while waiting for the child.

## What's covered

- `cap_enter`, `cap_sandboxed`
- `cap_rights_init`, `cap_rights_set`, `cap_rights_clear`, `cap_rights_limit`,
  `cap_rights_get`, `cap_rights_is_set`, `cap_rights_is_valid`
- `cap_ioctls_limit`
- `cap_fcntls_limit`
- `pdfork`, `pdgetpid`, `pdkill`
- `ProcessDescriptor`: `kill`, `wait` (with optional timeout), `close`, `pid`,
  `current_pid`
