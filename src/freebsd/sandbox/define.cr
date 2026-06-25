require "socket"

module FreeBSD::Sandbox
  # Default Capsicum rights applied to a `bind` listener fd when the directive
  # gives no explicit `rights:`. This is the minimal set that keeps Crystal's
  # event-loop `accept` working under `cap_enter`: `accept`/`listen` for the
  # socket op, `getsockname`/`getsockopt` for address/option queries the stdlib
  # makes, `event` + `fcntl` for the kqueue registration and non-blocking flag
  # management the fiber scheduler performs on the fd. Override per-directive
  # with `rights: [...]`, or skip limiting with `rights: false`.
  DEFAULT_LISTENER_RIGHTS = [
    :accept, :listen, :getsockname, :getsockopt, :event, :fcntl,
  ] of Symbol | ::FreeBSD::Capsicum::Capability::Right

  # Declare and enter a sandbox in one place. The block contains *directives*
  # (plain calls) describing the process; the macro emits them in the one
  # mandatory order and the program body that follows runs sandboxed.
  #
  # Phase order emitted:
  #
  # 1. **pre-runtime** — `audit_helper` / `helper` pdfork helpers (each injects
  #    its own `Crystal.main_user_code` override, so they fork before the
  #    Crystal runtime regardless of where they appear in the block).
  # 2. **post-runtime** — the rest runs once, guarded by
  #    `unless FreeBSD::Casper::Helper.is_helper` so a helper child never
  #    re-opens a Casper channel (the `cap_init` / `EDEADLK` trap):
  #    a. Casper services: `net`, `pwd`, `grp`, `sysctl`, `syslog`, `fileargs`.
  #    b. `open(name, Type) { handle }` — run the block as root, store the handle.
  #       `directory(name, path_or_paths)` — pre-open directory fd(s) for openat.
  #    c. `bind(name, host, port)` — open a privileged listener as root, store it.
  #    d. `user(...)` — privilege drop (groups → chroot → setgid → setuid → scrub).
  #    e. `FreeBSD::Capsicum.sandbox!` — enter capability mode.
  #
  # Each `open`/`bind` directive generates a **typed accessor** named after it:
  # `open("db", File) { File.open(...) }` makes `FreeBSD::Sandbox.db : File` available
  # in the sandboxed body. The accessor carries the handle's real static type
  # (no boxing, no runtime cast), so a wrong name or wrong type is a compile
  # error. Names must be valid Crystal method identifiers.
  #
  # Supported directives:
  #
  # - `user name, chroot: nil, scrub_env: true` — drop to a passwd user.
  # - `user uid: u, gid: g, username: nil, chroot: nil, scrub_env: true` — by id.
  # - `audit_helper name = "audit"` — BSM audit via pre-runtime pdfork helper.
  # - `helper(name) { |server| ... }` — custom pre-runtime pdfork helper.
  # - `net(mode) { |b| ... }` — `system.net` policy. `mode` may be a `Mode`, a
  #   `Symbol`, or an array of either (`net([:name2addr, :connect_dns]) { … }`).
  # - `connect_dns host, ports` / `connect_dns({host => ports, …})` — shorthand
  #   for the "let me reach these hosts" `system.net` policy (resolve + connect).
  #   `ports` is an `Int`/`String` or array (`connect_dns "example.com", [80, 443]`).
  # - `pwd { |s| ... }`, `grp { |s| ... }`, `sysctl { |s| ... }` — lookups.
  # - `tz_data` — prime the local timezone (`/etc/localtime`) before cap_enter so
  #   `Time.local` keeps working in the sandbox. No arguments.
  # - `syslog ident, options, facility` — `system.syslog`.
  # - `fileargs paths, ...` — `system.fileargs`.
  # - `open(name, Type, rights: [...]?) { handle }` — open a resource as root;
  #   the block must return a `Type`, exposed as the typed accessor
  #   `Sandbox.<name> : Type`. With `rights:` the handle's fd is limited via
  #   `cap_rights_limit` before `cap_enter`; `Type` must then be fd-bearing
  #   (`IO::FileDescriptor` or `Socket`) or it is a compile error.
  # - `directory(name, path_or_paths, rights: [...]?, exact_rights: false)` —
  #   pre-open a directory fd (folders only) before `cap_enter` so files beneath
  #   it can be opened via `openat` from the sandbox. `path_or_paths` is a single
  #   path string or an array of them; the accessor `Sandbox.<name>` is a
  #   `Capsicum::Directory` (single) or `Array(Capsicum::Directory)` (array).
  #   Each handle is rights-limited (default `[:lookup, :read, :fstat]`). By
  #   default the rights `openat` and Crystal's IO machinery need are unioned in
  #   (`:lookup, :fcntl, :fstat, :seek`); pass `exact_rights: true` to apply
  #   exactly the listed rights (advanced — see `Capsicum::Directory.open`).
  #   Each handle is registered for transparent routing: `require
  #   "freebsd/capsicum/integrate/file"` routes `File.open`/`File.info?`/
  #   `File.exists?` beneath the base, and `freebsd/capsicum/integrate/dir`
  #   routes `Dir.children`/`Dir.entries`/`Dir.each_child`.
  # - `bind name, host, port, rights: [...]?` — privileged `TCPServer`;
  #   `Sandbox.<name> : TCPServer`. The listener fd is rights-limited before
  #   `cap_enter`: `rights:` overrides, `rights: false` skips, and when omitted
  #   `DEFAULT_LISTENER_RIGHTS` (a known-good accept/event-loop set) is applied.
  #
  # `rights:` elements may be `Symbol`s (`:accept`, `:read`, `:fstat`, …) or
  # `Capsicum::Capability::Right` constants, freely mixed in one array.
  #
  # ```
  # FreeBSD::Sandbox.define do
  #   user "nobody", chroot: "/var/empty"
  #   audit_helper
  #   net([:name2addr, :connect_dns]) { |b| b.allow_name2addr("example.com", "80") }
  #   open("db", File) { File.open("/var/db/app.sqlite", "r+") }
  #   bind "listener", "0.0.0.0", 8080
  # end
  #
  # db = FreeBSD::Sandbox.db             # => File
  # listener = FreeBSD::Sandbox.listener # => TCPServer
  # ```
  macro define(&block)
    {% directives = block.body.is_a?(Expressions) ? block.body.expressions : [block.body] %}

    # Generate a typed accessor + setter for every open/bind resource, inside
    # the FreeBSD::Sandbox module (define is called at the program's top level,
    # so we reopen the module explicitly). The class var is inferred to the
    # handle's concrete type from the setter's parameter; the getter exposes it
    # non-nil. The setter is invoked in sequence during phase 2 below.
    module ::FreeBSD::Sandbox
      {% for expr in directives %}
        {% if expr.is_a?(Call) && expr.name == "open" %}
          {% rtype = expr.args[1] %}
          # Concrete handle type stated by the `open` directive, so the class
          # var is `T?` and the getter returns `T` with no runtime cast or box.
          @@{{ expr.args[0].id }} : {{ rtype }}? = nil

          # :nodoc:
          def self.__set_{{ expr.args[0].id }}(handle : {{ rtype }}) : Nil
            @@{{ expr.args[0].id }} = handle
          end

          # The handle opened by the `{{ expr.args[0].id }}` directive, typed
          # `{{ rtype }}`. Raises if accessed before setup ran (e.g. in a
          # helper child).
          def self.{{ expr.args[0].id }} : {{ rtype }}
            @@{{ expr.args[0].id }}.not_nil!
          end
        {% elsif expr.is_a?(Call) && expr.name == "directory" %}
          # `directory` takes a single path or an array of paths. The accessor
          # type follows the argument: one path -> Directory, an array literal ->
          # Array(Directory). The class var is inferred from the setter param.
          {% if expr.args[1].is_a?(ArrayLiteral) %}
            {% dir_type = "Array(::FreeBSD::Capsicum::Directory)".id %}
          {% else %}
            {% dir_type = "::FreeBSD::Capsicum::Directory".id %}
          {% end %}
          @@{{ expr.args[0].id }} : {{ dir_type }}? = nil

          # :nodoc:
          def self.__set_{{ expr.args[0].id }}(handle : {{ dir_type }}) : Nil
            @@{{ expr.args[0].id }} = handle
          end

          # The directory handle(s) opened by the `{{ expr.args[0].id }}`
          # directive, typed `{{ dir_type }}`. Raises if accessed before setup
          # ran (e.g. in a helper child).
          def self.{{ expr.args[0].id }} : {{ dir_type }}
            @@{{ expr.args[0].id }}.not_nil!
          end
        {% elsif expr.is_a?(Call) && expr.name == "bind" %}
          @@{{ expr.args[0].id }} : ::TCPServer? = nil

          # :nodoc:
          def self.__set_{{ expr.args[0].id }}(handle : ::TCPServer) : Nil
            @@{{ expr.args[0].id }} = handle
          end

          # The `::TCPServer` bound by the `{{ expr.args[0].id }}` directive.
          # Raises if accessed before setup ran (e.g. in a helper child).
          def self.{{ expr.args[0].id }} : ::TCPServer
            @@{{ expr.args[0].id }}.not_nil!
          end
        {% end %}
      {% end %}
    end

    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      # --- Phase 1: pre-runtime helpers ------------------------------------
      # These macros inject their own Crystal.main_user_code override, forking
      # before the runtime. Emit them first so the override is in place.
      {% for expr in directives %}
        {% if expr.is_a?(Call) && expr.name == "audit_helper" %}
          FreeBSD::Casper.register_audit_helper(
            {% if expr.args.size > 0 %}{{ expr.args[0] }}{% else %}"audit"{% end %})
        {% elsif expr.is_a?(Call) && expr.name == "helper" %}
          FreeBSD::Casper::Helper.register(name: {{ expr.args[0] }}) {{ expr.block }}
        {% end %}
      {% end %}

      # --- Phase 2: post-runtime setup, privdrop, sandbox ------------------
      # One guard for the whole block: a pdfork helper child must not run any
      # of this (it owns no Casper channel; cap_init there deadlocks).
      unless FreeBSD::Casper::Helper.is_helper
        {% privdrop = nil %}
        {% for expr in directives %}
          {% if expr.is_a?(Call) %}
            {% if expr.name == "user" %}
              {% privdrop = expr %}
            {% elsif expr.name == "net" %}
              FreeBSD::Casper.register_net({{ expr.args[0] }}) {{ expr.block }}
            {% elsif expr.name == "connect_dns" %}
              FreeBSD::Casper.register_connect_dns({{ expr.args.splat }})
            {% elsif expr.name == "pwd" %}
              FreeBSD::Casper.register_pwd {{ expr.block }}
            {% elsif expr.name == "grp" %}
              FreeBSD::Casper.register_grp {{ expr.block }}
            {% elsif expr.name == "sysctl" %}
              FreeBSD::Casper.register_sysctl {{ expr.block }}
            {% elsif expr.name == "syslog" %}
              FreeBSD::Casper.register_syslog({{ expr.args.splat }})
            {% elsif expr.name == "fileargs" %}
              FreeBSD::Casper.register_fileargs({{ expr.args.splat }})
            {% elsif expr.name == "tz_data" %}
              ::FreeBSD::Sandbox.__prime_tz
            {% elsif expr.name == "open" %}
              ::FreeBSD::Sandbox.__set_{{ expr.args[0].id }}({{ expr.block.body }})
              {% rights = nil %}
              {% if expr.named_args %}{% for na in expr.named_args %}{% if na.name == "rights" %}{% rights = na.value %}{% end %}{% end %}{% end %}
              {% if rights != nil && rights != false %}
                {% rtype = expr.args[1] %}
                {% unless rtype.resolve <= IO::FileDescriptor || rtype.resolve <= Socket %}
                  {{ expr.raise "rights: requires an fd-bearing handle (IO::FileDescriptor or Socket), got #{rtype}" }}
                {% end %}
                ::FreeBSD::Sandbox.__apply_rights(::FreeBSD::Sandbox.{{ expr.args[0].id }}.fd, {{ rights }})
              {% end %}
            {% elsif expr.name == "directory" %}
              {% rights = nil %}
              {% exact = false %}
              {% if expr.named_args %}{% for na in expr.named_args %}{% if na.name == "rights" %}{% rights = na.value %}{% elsif na.name == "exact_rights" %}{% exact = na.value %}{% end %}{% end %}{% end %}
              {% if rights == nil %}{% rights = "[:lookup, :read, :fstat]".id %}{% end %}
              {% if expr.args[1].is_a?(ArrayLiteral) %}
                ::FreeBSD::Sandbox.__set_{{ expr.args[0].id }}(::FreeBSD::Sandbox.__open_directories({{ expr.args[1] }}, {{ rights }}, {{ exact }}))
              {% else %}
                ::FreeBSD::Sandbox.__set_{{ expr.args[0].id }}(::FreeBSD::Sandbox.__open_directory({{ expr.args[1] }}, {{ rights }}, {{ exact }}))
              {% end %}
            {% elsif expr.name == "bind" %}
              ::FreeBSD::Sandbox.__set_{{ expr.args[0].id }}(::FreeBSD::Sandbox.__bind_listener({{ expr.args[1] }}, {{ expr.args[2] }}))
              {% rights = nil %}
              {% rights_given = false %}
              {% if expr.named_args %}{% for na in expr.named_args %}{% if na.name == "rights" %}{% rights = na.value %}{% rights_given = true %}{% end %}{% end %}{% end %}
              {% if rights_given && rights == false %}
                # rights: false — keep the listener fd unrestricted.
              {% else %}
                ::FreeBSD::Sandbox.__apply_rights(
                  ::FreeBSD::Sandbox.{{ expr.args[0].id }}.fd,
                  {% if rights_given %}{{ rights }}{% else %}::FreeBSD::Sandbox::DEFAULT_LISTENER_RIGHTS{% end %})
              {% end %}
            {% elsif expr.name == "audit_helper" || expr.name == "helper" %}
              # handled in phase 1
            {% else %}
              {{ expr.raise "unknown FreeBSD::Sandbox directive: #{expr.name}" }}
            {% end %}
          {% else %}
            {{ expr.raise "FreeBSD::Sandbox.define block may only contain directive calls" }}
          {% end %}
        {% end %}

        # Privilege drop last (after every resource is open), then cap_enter.
        {% if privdrop %}
          ::FreeBSD::Sandbox.__privdrop_config(
            {% for arg in privdrop.args %}{{ arg }}, {% end %}
            {% if privdrop.named_args %}{% for na in privdrop.named_args %}{{ na.name }}: {{ na.value }}, {% end %}{% end %}
          ).drop!
        {% end %}
        FreeBSD::Capsicum.sandbox!
      end
    {% end %}
  end

  # The real user id the process is running as — after the `user` privilege
  # drop, this is the dropped-to uid. `getuid(2)` is permitted in capability
  # mode, so this works from the sandboxed body; it's the natural value for an
  # audit `subject` token. Returns the invoking uid when no `user` drop was
  # declared.
  def self.uid : LibC::UidT
    LibC.getuid
  end

  # The real group id the process is running as — after the `user` privilege
  # drop, the dropped-to gid (or the invoking gid when no drop was declared).
  # `getgid(2)` is permitted in capability mode. See `.uid`.
  def self.gid : LibC::GidT
    LibC.getgid
  end

  # :nodoc:
  # Prime the local timezone cache by forcing `Time::Location.local` to load
  # `/etc/localtime` now, while the filesystem is still reachable. The result is
  # memoized (`Time::Location.class_property local`), so every later `Time.local`
  # in the sandboxed body reuses it without touching the filesystem. Run as a
  # `tz_data` directive before privdrop / cap_enter.
  def self.__prime_tz : Nil
    Time::Location.local
  end

  # :nodoc:
  # Build a `PrivdropConfig` from a positional username form: `user "nobody"`.
  def self.__privdrop_config(username : String, *,
                             chroot : String? = nil,
                             scrub_env : Bool = true) : PrivdropConfig
    PrivdropConfig.new(username: username, chroot: chroot, scrub_env: scrub_env)
  end

  # :nodoc:
  # Build a `PrivdropConfig` from the id form: `user uid: u, gid: g`.
  def self.__privdrop_config(*, uid : LibC::UidT, gid : LibC::GidT,
                             username : String? = nil,
                             chroot : String? = nil,
                             scrub_env : Bool = true) : PrivdropConfig
    PrivdropConfig.new(uid: uid, gid: gid, username: username,
      chroot: chroot, scrub_env: scrub_env)
  end

  # :nodoc:
  # Open a privileged TCP listener bound to `host`:`port` without name
  # resolution. `host` must be a literal IP (e.g. "0.0.0.0", "127.0.0.1", "::").
  # Avoiding `getaddrinfo` matters because an installed Casper net policy routes
  # DNS through the limited helper — a `bind` during setup must not depend on it.
  def self.__bind_listener(host : String, port : Int) : ::TCPServer
    addr = ::Socket::IPAddress.new(host, port.to_i)
    server = ::TCPServer.new(addr.family)
    begin
      server.bind(addr)
      server.listen
    rescue ex
      server.close
      raise ex
    end
    server
  end

  # :nodoc:
  # Open `path` as a `Capsicum::Directory` (before cap_enter), limit its rights,
  # and register it for transparent `File.open` routing. Used by the single-path
  # form of the `directory` directive.
  def self.__open_directory(path : String,
                            rights : Enumerable(Symbol | ::FreeBSD::Capsicum::Capability::Right),
                            exact_rights : Bool = false) : ::FreeBSD::Capsicum::Directory
    dir = ::FreeBSD::Capsicum::Directory.open(path, rights: rights, exact_rights: exact_rights)
    ::FreeBSD::Capsicum.register_directory(dir)
    dir
  end

  # :nodoc:
  # Open and register each of `paths` (see `__open_directory`); used by the
  # array form of the `directory` directive. Returns the handles in order.
  def self.__open_directories(paths : Enumerable(String),
                              rights : Enumerable(Symbol | ::FreeBSD::Capsicum::Capability::Right),
                              exact_rights : Bool = false) : Array(::FreeBSD::Capsicum::Directory)
    paths.map { |path| __open_directory(path, rights, exact_rights) }
  end

  # :nodoc:
  # Build a `Capability::Rights` from a list of `Symbol`/`Right` and apply it as
  # the hard limit on `fd`. Used by the `open`/`bind` directives' `rights:`
  # option. Each element is coerced through `Right.from`, so `:accept` and
  # `Capsicum::Capability::Right::Accept` are interchangeable in one list.
  def self.__apply_rights(fd : Int32,
                          rights : Enumerable(Symbol | ::FreeBSD::Capsicum::Capability::Right)) : Nil
    set = ::FreeBSD::Capsicum::Capability::Rights.new
    rights.each { |right| set.set(::FreeBSD::Capsicum::Capability::Right.from(right)) }
    set.apply_to(fd)
  end
end
