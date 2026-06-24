require "../casper"
require "./integrate/dns"
require "./integrate/net"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_net")]
  lib LibCapNet
    type CapNetLimit = Void*

    # cap_net_limit_init modes (bitmask).
    CAPNET_ADDR2NAME            = 0x01_u64
    CAPNET_NAME2ADDR            = 0x02_u64
    CAPNET_DEPRECATED_ADDR2NAME = 0x04_u64
    CAPNET_DEPRECATED_NAME2ADDR = 0x08_u64
    CAPNET_CONNECT              = 0x10_u64
    CAPNET_BIND                 = 0x20_u64
    CAPNET_CONNECTDNS           = 0x40_u64

    fun cap_getaddrinfo(chan : LibCasper::CapChannel,
                        hostname : LibC::Char*,
                        servname : LibC::Char*,
                        hints : Void*,
                        res : Void**) : Int32

    fun cap_bind(chan : LibCasper::CapChannel,
                 s : Int32,
                 addr : LibC::Sockaddr*, addrlen : LibC::SocklenT) : Int32

    fun cap_connect(chan : LibCasper::CapChannel,
                    s : Int32,
                    addr : LibC::Sockaddr*, addrlen : LibC::SocklenT) : Int32

    # Limit set construction.
    # All cap_net_limit_* functions return the (possibly updated) limit pointer
    # on success, or NULL on failure (with errno set). This matches the C API:
    #   cap_net_limit_t *cap_net_limit_connect(cap_net_limit_t *, ...)
    fun cap_net_limit_init(chan : LibCasper::CapChannel, mode : UInt64) : CapNetLimit
    fun cap_net_limit_bind(limit : CapNetLimit, sa : LibC::Sockaddr*, salen : LibC::SocklenT) : CapNetLimit
    fun cap_net_limit_connect(limit : CapNetLimit, sa : LibC::Sockaddr*, salen : LibC::SocklenT) : CapNetLimit
    fun cap_net_limit_addr2name_family(limit : CapNetLimit, families : Int32*, nfamilies : LibC::SizeT) : CapNetLimit
    fun cap_net_limit_addr2name(limit : CapNetLimit, sa : LibC::Sockaddr*, salen : LibC::SocklenT) : CapNetLimit
    fun cap_net_limit_name2addr_family(limit : CapNetLimit, families : Int32*, nfamilies : LibC::SizeT) : CapNetLimit
    fun cap_net_limit_name2addr(limit : CapNetLimit, name : LibC::Char*, serv : LibC::Char*) : CapNetLimit

    # Applies and frees the limit handle.
    fun cap_net_limit(limit : CapNetLimit) : Int32
    fun cap_net_free(limit : CapNetLimit) : Void
  end
{% end %}

require "socket"

module FreeBSD::Casper
  # Casper's `system.net` service: policy-checked `bind(2)` and `connect(2)`
  # operations for a sandboxed process. The helper validates each operation
  # against a configured limit set (which addresses may be connected/bound to,
  # which address families may be resolved) and lets the syscall proceed only
  # if the policy permits.
  #
  # Note that on FreeBSD plain `bind`/`connect` already work in capability
  # mode for ordinary IP sockets — the value of `system.net` is the policy
  # layer, not the syscalls themselves.
  class Service::Net < Service
    # Bitmask passed to `#limit` indicating which operations the limit set
    # constrains. Operations not selected here keep their current limit
    # (initially: unrestricted) on the helper side.
    @[Flags]
    enum Mode : UInt64
      Addr2Name           = 0x01
      Name2Addr           = 0x02
      DeprecatedAddr2Name = 0x04
      DeprecatedName2Addr = 0x08
      Connect             = 0x10
      Bind                = 0x20
      ConnectDNS          = 0x40

      # Coerce a `Symbol`, a `Mode`, or an `Enumerable` of either into a single
      # `Mode`. Symbols name members case-insensitively with `_` word separators
      # (`:name2addr` → `Name2Addr`, `:connect_dns` → `ConnectDNS`); an array is
      # OR-folded so `[:name2addr, :connect_dns]` replaces
      # `Mode::Name2Addr | Mode::ConnectDNS`. Raises `ArgumentError` naming a bad
      # symbol.
      def self.from(value : Symbol | Mode) : Mode
        case value
        in Mode   then value
        in Symbol then parse(value.to_s)
        end
      end

      # :ditto:
      def self.from(values : Enumerable(Symbol | Mode)) : Mode
        values.reduce(Mode::None) { |acc, v| acc | from(v) }
      end
    end

    # Connect `socket` to `addr` via the helper. Equivalent to `cap_connect(3)`.
    def connect(socket : ::Socket, addr : ::Socket::Address) : Nil
      connect_raw(socket.fd, addr.to_unsafe, addr.size.to_u32)
    end

    # Bind `socket` to `addr` via the helper. Equivalent to `cap_bind(3)`.
    def bind(socket : ::Socket, addr : ::Socket::Address) : Nil
      bind_raw(socket.fd, addr.to_unsafe, addr.size.to_u32)
    end

    # Low-level connect, takes a raw `LibC::Sockaddr*`. Used by
    # `casper/integrate/net` which receives the raw sockaddr from Crystal's
    # `system_connect` hook.
    #
    # `cap_connect` is an RPC: it sends the fd to the casper helper via
    # SCM_RIGHTS and the helper calls `connect(2)`. If the socket is
    # O_NONBLOCK the kernel would return EINPROGRESS before the connection
    # completes, confusing the RPC layer. Temporarily clear O_NONBLOCK to let
    # `connect(2)` block until the TCP handshake finishes, then restore it.
    def connect_raw(fd : Int32, sa : LibC::Sockaddr*, sa_len : LibC::SocklenT) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        flags = LibC.fcntl(fd, LibC::F_GETFL, 0)
        nonblock = flags >= 0 && (flags & LibC::O_NONBLOCK) != 0
        LibC.fcntl(fd, LibC::F_SETFL, flags & ~LibC::O_NONBLOCK) if nonblock
        begin
          if LibCapNet.cap_connect(@handle, fd, sa, sa_len) != 0
            raise ::Socket::ConnectError.from_errno("cap_connect")
          end
        ensure
          LibC.fcntl(fd, LibC::F_SETFL, flags) if nonblock
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Low-level bind: takes a raw sockaddr pointer. Used by `casper/integrate/net`.
    def bind_raw(fd : Int32, sa : LibC::Sockaddr*, sa_len : LibC::SocklenT) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        if LibCapNet.cap_bind(@handle, fd, sa, sa_len) != 0
          raise ::Socket::BindError.from_errno("cap_bind")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # DNS resolution via the Net service channel. `cap_net` provides
    # `cap_getaddrinfo` directly, making `system.dns` unnecessary.
    # Required when using `Mode::Name2Addr` or `Mode::ConnectDNS` limits.
    #
    # Returns the raw `LibC::Addrinfo*` chain; the caller must release it
    # with `LibC.freeaddrinfo`. Raises `Socket::Addrinfo::Error` on failure.
    def raw_getaddrinfo(host : String,
                        service : String? = nil,
                        hints : LibC::Addrinfo* = Pointer(LibC::Addrinfo).null) : LibC::Addrinfo*
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        res = Pointer(LibC::Addrinfo).null
        svc = service.nil? ? Pointer(LibC::Char).null : service.to_unsafe
        rc = LibCapNet.cap_getaddrinfo(@handle, host, svc,
          hints.as(Void*), pointerof(res).as(Void**))
        unless rc.zero?
          raise ::Socket::Addrinfo::Error.from_os_error(nil, Errno.new(rc), domain: host)
        end
        res
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Build and apply a limit set. The block yields a `LimitBuilder`; once it
    # returns, the limit is committed to the helper and takes effect for all
    # subsequent operations on this service.
    #
    # `mode` may be a `Mode`, a `Symbol`, or an array of either (OR-folded);
    # `[:connect, :bind]` is equivalent to `Mode::Connect | Mode::Bind`.
    #
    # ```
    # net.limit([:connect, :bind]) do |b|
    #   b.allow_connect(Socket::IPAddress.new("127.0.0.1", 8080))
    #   b.allow_bind(Socket::IPAddress.new("0.0.0.0", 0))
    # end
    # ```
    def limit(mode : Mode | Symbol | Enumerable(Symbol | Mode), & : LimitBuilder ->) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        mode = Mode.from(mode)
        handle = LibCapNet.cap_net_limit_init(@handle, mode.value)
        raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_init") if handle.null?
        committed = false
        builder = LimitBuilder.new(handle)
        begin
          yield builder
          if LibCapNet.cap_net_limit(handle) != 0
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit")
          end
          committed = true
        ensure
          # cap_net_limit consumes the handle on success; free only on failure.
          LibCapNet.cap_net_free(handle) unless committed
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Helper passed to `Service::Net#limit`. Each `allow_*` call narrows the
    # set of operations the helper will accept once `cap_net_limit` is applied.
    class LimitBuilder
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        @handle : LibCapNet::CapNetLimit

        protected def initialize(@handle : LibCapNet::CapNetLimit)
        end

        # Allow `connect(2)` to `addr`. Use with `Mode::Connect` in the `limit` call.
        def allow_connect(addr : ::Socket::Address) : Nil
          if LibCapNet.cap_net_limit_connect(@handle, addr.to_unsafe, addr.size.to_u32).null?
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_connect")
          end
        end

        # Allow `bind(2)` to `addr`. Use with `Mode::Bind` in the `limit` call.
        def allow_bind(addr : ::Socket::Address) : Nil
          if LibCapNet.cap_net_limit_bind(@handle, addr.to_unsafe, addr.size.to_u32).null?
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_bind")
          end
        end

        # Allow reverse DNS (`getnameinfo`) for addresses in the given address families.
        # Use with `Mode::Addr2Name` in the `limit` call.
        def allow_addr2name_family(*families : ::Socket::Family) : Nil
          arr = families.map(&.value.to_i32).to_a
          if LibCapNet.cap_net_limit_addr2name_family(@handle, arr.to_unsafe, arr.size.to_u64).null?
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_addr2name_family")
          end
        end

        # Restrict reverse DNS (`getnameinfo`) to a specific address. Use
        # together with `Mode::Addr2Name` in the `limit` call.
        def allow_addr2name(addr : ::Socket::IPAddress) : Nil
          if LibCapNet.cap_net_limit_addr2name(@handle, addr.to_unsafe, addr.size.to_u32).null?
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_addr2name")
          end
        end

        # Allow forward DNS (`getaddrinfo`) for the given address families.
        # Use with `Mode::Name2Addr` in the `limit` call.
        def allow_name2addr_family(*families : ::Socket::Family) : Nil
          arr = families.map(&.value.to_i32).to_a
          if LibCapNet.cap_net_limit_name2addr_family(@handle, arr.to_unsafe, arr.size.to_u64).null?
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_name2addr_family")
          end
        end

        # Allow forward DNS for a specific hostname and optional service/port.
        # Use with `Mode::Name2Addr` in the `limit` call.
        # Per cap_net(3), when combined with `Mode::ConnectDNS`, restricts
        # cap_connect to addresses returned for this specific name.
        def allow_name2addr(name : String, service : String? = nil) : Nil
          svc = service.nil? ? Pointer(LibC::Char).null : service.to_unsafe
          if LibCapNet.cap_net_limit_name2addr(@handle, name, svc).null?
            raise ::FreeBSD::Capsicum::Error.from_errno("cap_net_limit_name2addr")
          end
        end

        # Allow forward DNS + `connect(2)` for `host` on each of `ports`. This is
        # the "let me reach this host" recipe: it adds an `allow_name2addr` per
        # port, which — combined with `Mode::Name2Addr | Mode::ConnectDNS` on the
        # `limit` call — permits `cap_getaddrinfo(host)` and then `cap_connect` to
        # the addresses it returns. `ports` may be a single `Int`/`String` or an
        # enumerable of them (`80`, `"443"`, `[80, 443]`).
        def allow_connect_dns(host : String, ports : Int | String | Enumerable) : Nil
          case ports
          when Int, String
            allow_name2addr(host, ports.to_s)
          else
            ports.each { |p| allow_name2addr(host, p.to_s) }
          end
        end
      {% else %}
        protected def initialize(@handle : Void*)
        end

        def allow_connect_dns(host : String, ports : Int | String | Enumerable) : Nil
          raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
        end
      {% end %}
    end

    # Set up the "let me reach these hosts" policy in one call: applies the
    # `Mode::Name2Addr | Mode::ConnectDNS` limit and allows forward DNS + connect
    # for each given host/port. After this the sandboxed process can
    # `cap_getaddrinfo` and `cap_connect` to the listed hosts (on the listed
    # ports) and nothing else.
    #
    # ```
    # net.connect_dns("example.com", 80)        # single host, single port
    # net.connect_dns("example.com", [80, 443]) # single host, several ports
    # ```
    def connect_dns(host : String, ports : Int | String | Enumerable) : Nil
      limit(Mode::Name2Addr | Mode::ConnectDNS) do |b|
        b.allow_connect_dns(host, ports)
      end
    end

    # Multi-host form. Each value is a single port or an enumerable of ports.
    #
    # ```
    # net.connect_dns({
    #   "example.com"     => 80,
    #   "api.example.com" => [80, 443],
    # })
    # ```
    def connect_dns(hosts : Hash(String, _)) : Nil
      limit(Mode::Name2Addr | Mode::ConnectDNS) do |b|
        hosts.each { |host, ports| b.allow_connect_dns(host, ports) }
      end
    end
  end

  class Channel
    # Open the `system.net` Casper service on this channel.
    def net : Service::Net
      Service::Net.new(service("system.net"))
    end
  end

  @@net : Service::Net? = nil

  # The globally-installed Casper Net service, if any. When set, the
  # `casper/integrate/net` integration routes `Socket#connect` and
  # `Socket#bind` through this helper instead of `LibC.connect`/`LibC.bind`.
  def self.net? : Service::Net?
    @@net
  end

  def self.install_net(service : Service::Net) : Service::Net
    @@net = service
  end

  # Open a Casper channel, take its `system.net` service, install it
  # globally, and close the channel. Returns the service.
  def self.install_net! : Service::Net
    chan = Channel.open
    svc = chan.net
    chan.close
    install_net(svc)
  end

  def self.uninstall_net : Nil
    @@net = nil
  end

  # Install the Casper `system.net` service with a policy limit, injecting
  # a `Crystal.main_user_code` override that runs before the Crystal runtime
  # starts. This is the ergonomic alternative to writing the override by hand.
  #
  # Call at the **top level** of your program (outside any method), before
  # `require`-ing any code that touches the event loop.
  #
  # ```
  # require "freebsd/casper/net"
  # require "freebsd/casper/integrate/dns"
  # require "freebsd/casper/integrate/net"
  #
  # FreeBSD::Casper.register_net([:name2addr, :connect_dns]) do |b|
  #   b.allow_name2addr("example.com", "80")
  # end
  #
  # FreeBSD::Capsicum.sandbox!
  # HTTP::Client.get("http://example.com/") # routed through the net helper
  # ```
  macro register_net(mode, &block)
    \{% if flag?(:freebsd) || flag?(:dragonfly) %}
      # Guard: helper children (pdfork'd before the runtime) must not call
      # cap_init — they don't own the net channel and cap_init's internal fork
      # would create a crossed channel pair → EDEADLK on the first getaddrinfo.
      unless FreeBSD::Casper::Helper.is_helper
        _chan = FreeBSD::Casper::Channel.open
        _net  = _chan.net
        _net.limit({{mode}}) {{block}}
        _chan.close
        FreeBSD::Casper.install_net(_net)
      end
    \{% end %}
  end

  # Install the `system.net` service with a "reach these hosts" policy in one
  # call — the `connect_dns` shorthand for the common case. Accepts the same
  # arguments as `Service::Net#connect_dns`: a single `host` + `ports`, or a
  # `Hash` of host => ports. Like `register_net`, this opens and installs the
  # service C-style at top level and is a no-op in a pdfork helper child.
  #
  # ```
  # FreeBSD::Casper.register_connect_dns("example.com", 80)
  # # or several:
  # FreeBSD::Casper.register_connect_dns({"example.com" => 80, "api" => [80, 443]})
  #
  # FreeBSD::Capsicum.sandbox!
  # HTTP::Client.get("http://example.com/") # routed through the net helper
  # ```
  macro register_connect_dns(*args)
    \{% if flag?(:freebsd) || flag?(:dragonfly) %}
      unless FreeBSD::Casper::Helper.is_helper
        _chan = FreeBSD::Casper::Channel.open
        _net  = _chan.net
        _net.connect_dns({{ args.splat }})
        _chan.close
        FreeBSD::Casper.install_net(_net)
      end
    \{% end %}
  end
end
