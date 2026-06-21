# FreeBSD::Casper

Crystal bindings for **[Capsicum]** — FreeBSD's in-kernel capability mode —
and **libcasper**, the userspace service framework that lets a sandboxed
process delegate privileged work to a trusted helper.

[Capsicum]: https://www.cl.cam.ac.uk/research/security/capsicum/

```crystal
require "freebsd/casper"
```

> **Platform:** FreeBSD primary, DragonFlyBSD best-effort. On other platforms
> the shard compiles cleanly but any call raises
> `FreeBSD::Capsicum::UnsupportedPlatformError`.

## Sandbox the current process

```crystal
require "freebsd/casper"

FreeBSD::Capsicum.sandbox do
  # Capability mode is active. Global namespaces are gone:
  # File.open("/etc/passwd") here would raise (ECAPMODE).
  # Pre-opened FDs still work, subject to their rights.
end
```

`FreeBSD::Capsicum.sandbox!` enters capability mode without yielding — it is
one-way per process; once entered there is no going back.

## Restrict rights on a file descriptor

```crystal
require "freebsd/casper"

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

## Transparent `Socket` policy — DNS and connect via system.net

`system.net` (`cap_net(3)`) handles both DNS resolution and policy-checked
`connect`/`bind` in a single service. Use `Mode::Name2Addr | Mode::ConnectDNS`
to allow cap_getaddrinfo and then cap_connect to any address it returned.

`require "freebsd/casper/integrate/dns"` patches Crystal's `Socket::Addrinfo`
so that every standard-library lookup — `TCPSocket.new("host", port)`, URI host
resolution, `HTTP::Client.get`, … — silently routes through the Net helper once
it is installed. `require "freebsd/casper/integrate/net"` patches
`Crystal::System::Socket` so connect/bind go through the helper too.

```crystal
require "freebsd/casper"
require "freebsd/casper/net"
require "freebsd/casper/integrate/dns"
require "freebsd/casper/integrate/net"
require "http/client"

chan = FreeBSD::Casper::Channel.open
net  = chan.net

net.limit(
  FreeBSD::Casper::Service::Net::Mode::Name2Addr |
  FreeBSD::Casper::Service::Net::Mode::ConnectDNS
) do |b|
  b.allow_name2addr("example.com", "80")
end
chan.close

FreeBSD::Casper.install_net(net)
Time::Location.local     # prime /etc/localtime before sandboxing

FreeBSD::Capsicum.sandbox!

# Plain stdlib — DNS and connect both go through the Casper helper.
puts HTTP::Client.get("http://example.com").status_code
```

## Transparent `Socket` policy — restrict who you can connect/bind to

`require "freebsd/casper/integrate/net"` patches `Crystal::System::Socket`'s
`system_bind` and `system_connect` chokepoints so plain `TCPSocket.new(...)`
and `UDPSocket#bind` calls route through the Casper Net helper and are
policy-checked against a configured allow-list.

```crystal
require "freebsd/casper"
require "freebsd/casper/integrate/net"

net = FreeBSD::Casper.install_net!
net.limit(FreeBSD::Casper::Service::Net::Mode::Connect |
          FreeBSD::Casper::Service::Net::Mode::Bind) do |builder|
  builder.allow_connect(Socket::IPAddress.new("93.184.216.34", 443))
  builder.allow_bind(Socket::IPAddress.new("0.0.0.0", 0))
end

FreeBSD::Capsicum.sandbox!

# Stdlib code, no Casper API in sight. The helper validates each connect.
TCPSocket.new("93.184.216.34", 443)   # ok
TCPSocket.new("8.8.8.8", 53)          # raises Socket::ConnectError — outside policy
```

This is *defense in depth*, not "make stdlib work" — plain `connect`/`bind`
already work under `cap_enter` on FreeBSD. The helper adds a policy layer.

Caveats: `cap_connect` is synchronous, so `Socket#connect(timeout:)` semantics
are coarsened (the call blocks cooperatively via `Fiber.syscall` until it
succeeds or the kernel times it out). Only address-bearing operations are hooked
— `listen`/`accept`/`send`/`recv` keep their stdlib paths.

## Custom helpers — your own Casper-style privsep service in Crystal

If the shipped services don't cover what your sandboxed child needs to delegate,
`FreeBSD::Casper::Helper.spawn` gives you the same architecture in pure Crystal:
forks a trusted helper that serves requests, returns a `Client` to the calling
process. They speak a small length-prefixed wire protocol over a `UNIXSocket`
pair. No `casperd` plugin `.so` required.

On FreeBSD/DragonFly the helper's process title is set to `progname.name`
(e.g. `myapp.calc`), matching the `system.net` naming convention used by
`casperd` service workers. Unnamed helpers use `progname.helper`.

**Raw API** — useful when you need full control over op names and bytes:

```crystal
require "freebsd/casper"

client = FreeBSD::Casper::Helper.spawn(name: "files") do |server|
  # Forked helper — unsandboxed. Loops until the caller closes its end.
  server.serve do |op, payload|
    case op
    when "read" then File.read(String.new(payload)).to_slice
    when "ping" then "pong".to_slice
    else             raise "unknown op: #{op}"
    end
  end
end

# Caller — sandboxed, communicates via the client handle.
FreeBSD::Capsicum.sandbox!

puts String.new(client.request("ping"))             # => "pong"
puts String.new(client.request("read", "/etc/hosts".to_slice))
# ps shows: myapp.files
```

**Typed API** — declare request/response structs and let the helper route and
serialize automatically. The default codec is `FreeBSD::Casper::Codec::NVList`
(uses `FreeBSD::NVList::Serializable`); pass `codec: FreeBSD::Casper::Codec::JSON`
for JSON-backed structs:

```crystal
require "freebsd/casper"

record ReadFile, path : String do
  include FreeBSD::NVList::Serializable
end

record FileContent, data : String do
  include FreeBSD::NVList::Serializable
end

client = FreeBSD::Casper::Helper.spawn(name: "files") do |server|
  server.on(ReadFile) { |req| FileContent.new(data: File.read(req.path)) }
  server.serve_typed
end

FreeBSD::Capsicum.sandbox!

content = client.request(ReadFile.new(path: "/etc/hosts"), FileContent)
puts content.data   # fully typed String
```

Exceptions raised inside the helper are caught, serialized, and re-raised in
the caller as `FreeBSD::Casper::Helper::RemoteError`. An unrecognized op in the
typed dispatch raises `RemoteError` with message `"unknown op: <T.name>"`. A
single `Client` is not internally multiplexed; wrap it in a queue if you need
concurrent requests.

**Pre-runtime helper via `pdfork`** — the safest pattern: fork before the Crystal
runtime starts so neither child nor parent inherits a live event loop. The trick
is that both sides call `previous_def` inside the fork, so each process gets its
own fully-initialised runtime. The program body then checks a flag to decide
whether to act as server or client. This lets the helper use plain Crystal IO
(`File.read`, etc.) with no restrictions.

```crystal
require "socket"
require "freebsd/casper/helper"

module G
  class_property is_helper = false
  class_property helper_fd = -1
  class_property client_fd = -1
  class_property pd : FreeBSD::Capsicum::ProcessDescriptor?
end

def Crystal.main_user_code(argc : Int32, argv : UInt8**)
  {% if flag?(:freebsd) %}
    fds = uninitialized LibC::Int[2]
    LibC.socketpair(LibC::AF_UNIX, LibC::SOCK_STREAM, 0, fds)

    G.pd = FreeBSD::Capsicum.pdfork do
      LibC.close(fds[0])
      G.helper_fd = fds[1]
      G.is_helper = true
      previous_def    # child gets its own full runtime
      0
    end

    LibC.close(fds[1])
    G.client_fd = fds[0]
  {% end %}
  previous_def        # parent gets its own full runtime
  {% if flag?(:freebsd) %}
    G.pd.try { |p| p.wait; p.close }
  {% end %}
end

# Program body — full runtime available in both processes.
if G.is_helper
  sock = UNIXSocket.new(fd: G.helper_fd, type: Socket::Type::STREAM)
  FreeBSD::Casper::Helper::Server(FreeBSD::Casper::Codec::NVList).new(sock).serve do |op, payload|
    case op
    when "read" then File.read(String.new(payload)).to_slice  # plain Crystal IO
    when "ping" then "pong".to_slice
    else raise "unknown op: #{op}"
    end
  end
else
  client = FreeBSD::Casper::Helper::Client(FreeBSD::Casper::Codec::NVList).new(
    UNIXSocket.new(fd: G.client_fd, type: Socket::Type::STREAM), "files")
  FreeBSD::Capsicum.sandbox!
  puts String.new(client.request("ping"))             # => "pong"
  puts String.new(client.request("read", "/etc/hosts".to_slice))
  client.close
end
```

## BSM audit writes from a sandbox — `freebsd/casper/audit_helper`

`au_open(3)` returns -1 inside capability mode — the kernel audit pipe is
unavailable there. `freebsd/casper/audit_helper` solves this with a
`pdfork`-based helper that holds the audit pipe before the sandbox is entered
and serves `AuditHelper::Request` messages over NVList.

`AuditHelper::Event` mirrors the `FreeBSD::Audit::Event` API exactly — swap
the module name and everything else is the same:

```crystal
require "freebsd/casper/audit_helper"

FreeBSD::Casper.register_audit_helper   # top-level — forks helper before sandbox

FreeBSD::Capsicum.sandbox!

FreeBSD::Casper::AuditHelper::Event.write(FreeBSD::Audit::AUE::Authentication) do |r|
  r.subject uid: LibC.getuid.to_u32
  r.text "user=admin method=password"
  r.address "203.0.113.42"
  r.return_success
end

FreeBSD::Casper::AuditHelper::Event.write_activity(
  FreeBSD::Audit::Authentication::Activity::Logon
) do |r|
  r.subject
  r.text "user=admin"
  r.return_success
end

# Dry-run — constructs tokens but discards the record (no live auditd needed).
FreeBSD::Casper::AuditHelper::Event.discard(FreeBSD::Audit::AUE::Authentication) do |r|
  r.text "test record"
  r.return_success
end
```

`register_audit_helper` injects a `Crystal.main_user_code` override (chained
via `previous_def`, so it stacks with `register_syslog` etc.) that calls
`pdfork` before `__crystal_main`, gives the helper its own full Crystal
runtime, and installs the connected `Client` into
`FreeBSD::Casper.audit_helper!` in the parent process.

Helper children automatically drop every Casper service handle inherited from
the parent (net, grp, pwd, sysctl, syslog, fileargs, audit) before running, so a
child never reuses the parent's helper channels. This means `register_audit_helper`
and the `register_*` service macros can be stacked in **any order** — the program
behaves identically regardless of how the top-level `register_*` calls are arranged.

The helper replicates the `au_to_*` token-construction logic from
`FreeBSD::Audit::Record` and mirrors its ownership contract: if `au_write`
returns -1 (token not consumed), the token is freed with `au_free_token`.
Credentials (`uid`, `egid`, `ruid`, `rgid`, `pid`) are captured in the
sandboxed caller and transmitted to the helper, so audit records carry the
caller's identity rather than the helper's.

## Crystal `Log` to syslog from a sandbox

`require "freebsd/casper/integrate/log"` adds
`FreeBSD::Casper::Log::SyslogBackend`, a `Log::Backend` that forwards each
`Log::Entry` to `syslogd(8)` via Casper's `system.syslog` helper. Severities
map onto syslog priorities (`fatal` → `crit`, `error` → `err`, `warn` →
`warning`, `notice`/`info`/`debug` as is, `trace` → `debug`).

```crystal
require "freebsd/casper"
require "freebsd/casper/integrate/log"

syslog = FreeBSD::Casper.install_syslog!(
  ident: "myapp",
  options: FreeBSD::Casper::Service::Syslog::LogOption::Pid,
  facility: FreeBSD::Casper::Service::Syslog::Facility::Local0,
)
Log.setup(:info, FreeBSD::Casper::Log::SyslogBackend.new(syslog))
FreeBSD::Capsicum.sandbox!

Log.info { "ready to serve" }
```

Unlike the file/net hooks this is *not* monkey-patching — it is a normal
`Log::Backend` you opt into via `Log.setup`. The underlying
`FreeBSD::Casper::Service::Syslog` (`openlog`/`syslog`/`closelog`/`log_mask=`)
is also usable directly for code that doesn't go through Crystal's `Log`.

> **Caveat:** `Log::Entry` records a `Time.local` timestamp. `Time.local` reads
> `/etc/localtime` on its first call, which is blocked inside capability mode.
> Call `Time.local` once **before** `FreeBSD::Capsicum.sandbox!` to prime the cache:
>
> ```crystal
> Time.local   # prime /etc/localtime before entering capability mode
> FreeBSD::Capsicum.sandbox!
> Log.info { "ready" }
> ```

## Privsep with `pdfork` — fork a child you can still control from a sandbox

`pdfork(2)` forks a child and returns it as a *file descriptor* rather than a
PID. The descriptor stays valid after `cap_enter` (capability mode wipes the
PID namespace but not your fds), so the parent can `kill`/`close` the child
from inside the sandbox — the canonical Capsicum privsep pattern.

`FreeBSD::Capsicum.pdfork` is safest when called **before the Crystal runtime
starts** — from a `Crystal.main_user_code` override, before `previous_def` —
because neither child nor parent inherits a live event loop. When called after
the runtime has started the child reinitialises its event loop automatically
(via `Process.after_fork_child_callbacks`), so `sleep`, timers, and sockets
work, but GC state and open file descriptors are shared at the fork point.

The child block can call `previous_def` itself to start a full Crystal runtime
in the child too (see the pre-runtime helper section above for that pattern).
For a minimal child that just does a fixed task and exits:

```crystal
require "freebsd/casper"

def Crystal.main_user_code(argc : Int32, argv : UInt8**)
  pd = FreeBSD::Capsicum.pdfork do
    # Minimal child — no Crystal runtime. Use LibC syscalls only.
    0   # exit code
  end

  previous_def    # parent's runtime starts here

  # pd stays valid after sandbox!
  pd.pid                          # global PID (logging only — unusable in cap mode)
  pd.current_pid                  # nil once the kernel has reaped the child
  pd.kill(Signal::TERM)
  status = pd.wait                # blocks via kqueue/EVFILT_PROCDESC; works in cap mode
  status.try(&.exit_code)         # => Int32?, just like Process::Status
  pd.wait(500.milliseconds)       # => nil on timeout (child still running)
  pd.close                        # SIGKILL + reap (unless created with daemon: true)
end
```

Exceptions raised inside the child block are caught and logged to stderr; the
child exits with status 1 rather than escaping.

## Transparent `File` ops — work on pre-declared paths from a sandbox

`require "freebsd/casper/integrate/file"` patches `Crystal::System::File` so
plain stdlib calls on paths declared up-front route through the Casper helper:

| Stdlib call | Hooked to |
| --- | --- |
| `File.open` / `File.read` / `File.each_line` | `fileargs_open` |
| `File.info` / `File.info?` | `fileargs_lstat` |
| `File.exists?` | `fileargs_lstat` (truthy on success) |
| `File.real_path` | `fileargs_realpath` |

Undeclared paths fall through to libc — the require is safe to load
unconditionally. To enable `info?`/`exists?` and `real_path` you must opt in at
FileArgs creation via `fa_flags`:

```crystal
require "freebsd/casper"
require "freebsd/casper/integrate/file"

FreeBSD::Casper.install_fileargs!(
  ["/etc/hosts", "/etc/resolv.conf"],
  flags: LibC::O_RDONLY,
  fa_flags: FreeBSD::Casper::Service::FileArgs::OPEN |
            FreeBSD::Casper::Service::FileArgs::LSTAT |
            FreeBSD::Casper::Service::FileArgs::REALPATH,
)
FreeBSD::Capsicum.sandbox!

File.read("/etc/hosts")            # works
File.exists?("/etc/hosts")         # true
File.info("/etc/hosts").size       # works
File.real_path("/etc/hosts")       # "/etc/hosts"
File.read("/etc/passwd")           # raises File::Error (undeclared)
```

Paths are matched *exactly* as declared (no symlink resolution, no `..`
normalization). `info?(follow_symlinks: true)` is downgraded to `lstat` because
fileargs only exposes `lstat` — observable difference only if the declared path
is itself a symlink. `Dir.glob`, `Dir.entries`, and similar directory operations
are *not* hooked (fileargs is single-path).

## Password / group / sysctl lookups

```crystal
require "freebsd/casper"

chan = FreeBSD::Casper::Channel.open
pwd  = chan.pwd
grp  = chan.grp
sys  = chan.sysctl

pwd.limit_users(names: ["root", "nobody"])
sys.limit({"kern.ostype" => FreeBSD::Casper::Service::Sysctl::Mode::Read})
chan.close

FreeBSD::Capsicum.sandbox!

pwd.getpwnam("root").try(&.shell)         # => "/bin/sh"
grp.getgrgid(0_u32).try(&.name)           # => "wheel"
sys.get_string("kern.ostype")             # => "FreeBSD"
```

## What's covered (v0.1)

- Capsicum: `cap_enter`, `cap_sandboxed`, rights init/set/clear/limit/get,
  `cap_ioctls_limit`, `cap_fcntls_limit`, process descriptors (`pdfork`,
  `pdgetpid`, `pdkill`).
- libcasper core: `cap_init`, `cap_service_open`, `cap_clone`, `cap_close`.
- Services: `system.pwd`, `system.grp`, `system.sysctl`,
  `system.fileargs`, `system.net`, `system.syslog`.
- Stdlib integrations:
  - `freebsd/casper/integrate/dns` — `Socket::Addrinfo.getaddrinfo` (covers
    `TCPSocket`, `URI`, `HTTP::Client`) routed through `system.net`.
  - `freebsd/casper/integrate/file` — `File.open`, `File.info?`, `File.exists?`,
    `File.real_path` for declared paths.
  - `freebsd/casper/integrate/net` — `Socket#bind`, `Socket#connect` enforce a
    `cap_net` allow-list.
  - `freebsd/casper/integrate/log` — `Log::Backend` that writes to `syslogd(8)`
    through the Casper helper.
- Pure-Crystal Casper-style helpers: `FreeBSD::Casper::Helper.spawn` for
  building your own trusted-parent / sandboxed-child pair when the shipped
  services don't fit.
- `freebsd/casper/audit_helper` — capsicum-safe BSM audit writes via a
  `pdfork`-based helper; `AuditHelper::Event` mirrors `FreeBSD::Audit::Event`.
