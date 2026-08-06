# FreeBSD::Sandbox

`FreeBSD::Sandbox.define` is the recommended front door for sandboxing a
whole process: declare the user it drops to, the Casper resources it uses,
the ports it binds, and any resources it opens up front, all in one block.
It composes the lower-level building blocks — `FreeBSD::Privdrop`,
`FreeBSD::Capsicum`, `FreeBSD::Casper` — and runs them in the one mandatory
order, so callers don't have to memorise the pre-runtime / post-runtime /
privdrop / `cap_enter` sequence or wire up the helper-child guards by hand.

```crystal
require "freebsd/sandbox"
```

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. `FreeBSD::Sandbox::SUPPORTED`
> reports which. On other platforms the directives that touch Capsicum/Casper
> are compiled out.

## One-shot sandbox declaration — `FreeBSD::Sandbox.define`

The pieces below (helpers, services, privilege drop, `cap_enter`) each fire at a
different point in the process lifecycle and must run in one specific order:
pre-runtime `pdfork` helpers, then post-runtime resource setup, then the
privilege drop, then capability mode. Wiring that by hand is fiddly and easy to
get subtly wrong (a helper child that re-opens a Casper channel deadlocks).

```crystal
require "freebsd/sandbox"
require "freebsd/casper/net"
require "freebsd/casper/integrate/dns"
require "freebsd/casper/integrate/net"
require "http/client"

FreeBSD::Sandbox.define do
  user "nobody", chroot: "/var/empty"     # privilege drop target

  audit_helper                            # pre-runtime pdfork helper

  connect_dns "example.com", 80           # resolve + connect to this host only

  open("db", File, rights: [:read, :write, :fstat]) {         # opened as root
    File.open("/var/db/app.sqlite", "r+")
  }
  bind "listener", "0.0.0.0", 8080                            # privileged bind
end

# ---- everything below runs sandboxed (capability mode, dropped to nobody) ----

# Each open/bind directive generates a typed accessor named after it. A wrong
# name or wrong type is a compile error — no runtime cast.
db       = FreeBSD::Sandbox.db       # => File   (opened before the drop)
listener = FreeBSD::Sandbox.listener # => TCPServer

HTTP::Client.get("http://example.com/")  # policy-checked through the net helper
```

Phase order the macro emits:

| Phase | What runs |
| --- | --- |
| pre-runtime | `audit_helper` / `helper` pdfork helpers (before the Crystal runtime) |
| post-runtime | privileged `bind`, Casper services (`net`/`pwd`/`grp`/`sysctl`/`syslog`/`fileargs`), `tz_data`/`tls_context` priming, `open`/`directory`/`sqlite` blocks (as root) |
| rights | `cap_rights_limit` on `open`/`bind`/`directory`/`sqlite` fds declaring `rights:` (a `bind` with no `rights:` gets a known-good default listener set) |
| privdrop | `user` → groups → chroot → setgid → setuid → scrub |
| sandbox | `cap_enter` |

The whole post-runtime → sandbox sequence is wrapped in a single
`unless FreeBSD::Casper::Helper.is_helper` guard, so a `pdfork` helper child
never re-opens a Casper channel — the fix for the `cap_init`/`EDEADLK` deadlock,
written once instead of per service.

Every `bind` directive is emitted before any `net`/`connect_dns` directive,
**regardless of the order the caller wrote them in the block**: once a Casper
net policy is installed, `casper/integrate/net`'s `Socket#bind` override routes
*every* bind through `cap_bind`, and a `net`/`connect_dns` policy never grants
`Mode::Bind` — so a `bind` directive's own listener bind would be rejected if
it ran after policy installation.

### Directives

- `user name, chroot: nil, scrub_env: true` — drop to a passwd user.
- `user uid: u, gid: g, username: nil, chroot: nil, scrub_env: true` — by id.
- `audit_helper name = "audit"` — BSM audit via pre-runtime pdfork helper.
- `helper(name) { |server| ... }` — custom pre-runtime pdfork helper.
- `net(mode) { |b| ... }` — `system.net` policy. `mode` may be a `Mode`, a
  `Symbol`, or an array of either (`net([:name2addr, :connect_dns]) { … }`).
- `connect_dns host, ports` / `connect_dns({host => ports, …})` — shorthand
  for the "let me reach these hosts" `system.net` policy (resolve + connect).
  `ports` is an `Int`/`String` or array (`connect_dns "example.com", [80, 443]`).
- `pwd { |s| ... }`, `grp { |s| ... }`, `sysctl { |s| ... }` — lookups.
- `tz_data` — prime the local timezone (`/etc/localtime`) before cap_enter so
  `Time.local` keeps working in the sandbox. No arguments. Idempotent
  shorthand for `Sandbox.prime_tz_data!` — call that directly instead if
  priming needs to happen before some other pre-sandbox setup that itself
  must run before `Sandbox.define` starts (see below).
- `tls_context` — build one `OpenSSL::SSL::Context::Client` before cap_enter so
  its default CA verify paths (loaded from disk at construction time) are
  readable, then exposed via `Sandbox.tls_context` and
  `Sandbox.http_client_builder(timeout: ...)`. No arguments. Idempotent
  shorthand for `Sandbox.prime_tls_context!` — see below for why and when to
  call it standalone instead.
- `syslog ident, options, facility` — `system.syslog`.
- `fileargs paths, ...` — `system.fileargs`.
- `open(name, Type, rights: [...]?) { handle }` — open a resource as root;
  the block must return a `Type`, exposed as the typed accessor
  `Sandbox.<name> : Type`. With `rights:` the handle's fd is limited via
  `cap_rights_limit` before `cap_enter`; `Type` must then be fd-bearing
  (`IO::FileDescriptor` or `Socket`) or it is a compile error.
- `directory(name, path_or_paths, rights: [...]?, exact_rights: false)` —
  pre-open a directory fd (folders only) before `cap_enter` so files beneath
  it can be opened via `openat` from the sandbox. `path_or_paths` is a single
  path string or an array of them; the accessor `Sandbox.<name>` is a
  `Capsicum::Directory` (single) or `Array(Capsicum::Directory)` (array).
  Each handle is rights-limited (default `[:lookup, :read, :fstat]`). By
  default the rights `openat` and Crystal's IO machinery need are unioned in
  (`:lookup, :fcntl, :fstat, :seek`); pass `exact_rights: true` to apply
  exactly the listed rights (advanced — see `Capsicum::Directory.open`).
  Each handle is registered for transparent routing: `require
  "freebsd/capsicum/integrate/file"` routes `File.open`/`File.info?`/
  `File.exists?` beneath the base, and `freebsd/capsicum/integrate/dir`
  routes `Dir.children`/`Dir.entries`/`Dir.each_child`.
- `sqlite(name, path, rights: [...]?, exact_rights: false)` — pre-open the
  directory holding a SQLite database (`path`), register it, and install the
  `openat` VFS override so a WAL database reads and writes under `cap_enter`.
  The accessor `Sandbox.<name>` is the `Capsicum::Directory`. Rights default
  to `Capsicum::SQLITE_WAL_RIGHTS` (the full read+write WAL set). Requires
  `require "freebsd/capsicum/integrate/sqlite"` (and the `db`/`sqlite3`
  shards) in the program. Open the db by **absolute** path after the block.
- `bind name, host, port, rights: [...]?` — privileged `TCPServer`;
  `Sandbox.<name> : TCPServer`. The listener fd is rights-limited before
  `cap_enter`: `rights:` overrides, `rights: false` skips, and when omitted
  `DEFAULT_LISTENER_RIGHTS` (a known-good accept/event-loop set) is applied.
  Always binds before any `net`/`connect_dns` policy is installed, no matter
  where `bind` appears in the block.

`rights:` elements may be `Symbol`s (`:accept`, `:read`, `:fstat`, …) or
`Capsicum::Capability::Right` constants, freely mixed in one array.

## Priming pre-sandbox state — `tz_data` / `tls_context`

Some stdlib/OpenSSL state is loaded from disk lazily, on first use, which
means it silently breaks the first time it's touched *after* `cap_enter`
rather than at a predictable point. Both directives above front-load that
state before the sandbox closes the filesystem off:

- **`tz_data`** forces `Time::Location.local` to read `/etc/localtime` once,
  memoized by the stdlib so every later `Time.local` — including from the
  sandboxed body — reuses it.
- **`tls_context`** builds one `OpenSSL::SSL::Context::Client`.
  `OpenSSL::SSL::Context::Client#initialize` always calls
  `set_default_verify_paths`, which reads the OS CA bundle from disk at
  construction time — there is no process-wide caching of that read inside
  OpenSSL/Crystal, so a context built after `cap_enter` can never load a
  trust store, and any handshake through it fails with "certificate verify
  failed". Capsicum's file-open patch doesn't help here either — it only
  intercepts `Crystal::System::File`, and libssl's CA-bundle read is C code
  that never goes through that layer.

Both are backed by standalone methods — `Sandbox.prime_tz_data!` and
`Sandbox.prime_tls_context!` — callable independent of any `Sandbox.define`
call, and idempotent, so priming standalone and then again via the directive
in the same program is always safe. Reach for the standalone form when other
pre-sandbox setup (e.g. constructing an HTTP client a route/controller graph
depends on) must run *before* `Sandbox.define` even starts, making the
directive itself too late:

```crystal
require "freebsd/sandbox"

FreeBSD::Sandbox.prime_tls_context!
FreeBSD::Sandbox.prime_tz_data!

# ... other pre-sandbox setup that needs the primed state ...

FreeBSD::Sandbox.define do
  # ...
end
```

### `Sandbox.http_client_builder` — shared TLS context for injectable HTTP clients

Several shards (`kms`, `txmail`, …) accept an injectable HTTP client
constructor — a `Proc(URI, Time::Span, HTTP::Client)` — as a `client_builder:`
argument. `Sandbox.http_client_builder(timeout:)` returns exactly that shape,
built from the one `tls_context` primed before `cap_enter`, so every
`HTTP::Client` those shards build reuses it instead of each constructing (and
re-reading the CA bundle for) its own:

```crystal
FreeBSD::Sandbox.define do
  tls_context
  # ...
end

kms_client = KMS::Client.new(
  url: ENV["KMS_URL"],
  client_builder: FreeBSD::Sandbox.http_client_builder(timeout: 5.seconds),
)
```

The builder only attaches the TLS context for `https://` URIs —
`HTTP::Client.new` raises `ArgumentError` if given a TLS context for a plain
`http://` one — so one builder serves either scheme (e.g. a dev `http://`
`KMS_URL` vs. a production `https://` one).

## What's here

- `src/freebsd/sandbox.cr` — the `FreeBSD::Sandbox` module entry point,
  requires `privdrop`, `capsicum`, `casper`, and this sub-library.
- `src/freebsd/sandbox/define.cr` — the `Sandbox.define` macro and the
  `tz_data`/`tls_context` priming API documented above.
- `src/freebsd/sandbox/builder.cr` — `PrivdropConfig`, the runtime struct that
  collects a `user` directive's drop target and performs it via
  `FreeBSD::Privdrop.drop` once every resource is open.

See [`freebsd/casper`](../casper/README.md) for the underlying services
(`net`, `pwd`, `grp`, `sysctl`, `syslog`, `fileargs`, custom helpers) that the
directives above wrap, and [`freebsd/capsicum`](../capsicum/README.md) for the
raw capability-mode primitives.
