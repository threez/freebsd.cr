module FreeBSD::Casper
  # A Casper service channel — the connection to the trusted Casper helper
  # process. Opened *before* entering capability mode; services obtained from
  # it remain usable once sandboxed.
  class Channel
    @handle : LibCasper::CapChannel
    @closed = false

    protected def initialize(@handle : LibCasper::CapChannel)
    end

    # Open a new channel to the Casper daemon (`cap_init`).
    def self.open : Channel
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        handle = LibCasper.cap_init
        if handle.null?
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_init")
        end
        force_blocking(handle)
        new(handle)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Open a service on this channel. Returns the channel for the service.
    def service(name : String) : LibCasper::CapChannel
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        svc = LibCasper.cap_service_open(@handle, name)
        if svc.null?
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_service_open(#{name})")
        end
        Channel.force_blocking(svc)
        svc
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # libcasper's channel RPC (`cap_send_nvlist`/`cap_recv_nvlist`, used by
    # `cap_getaddrinfo` etc.) does a synchronous send-then-recv and assumes the
    # underlying socket is **blocking**. Under the Crystal runtime the channel
    # socket is created `O_NONBLOCK`, so a synchronous `recv` can see `EAGAIN`,
    # which libcasper surfaces as `EDEADLK` ("Resource deadlock avoided"). Clear
    # `O_NONBLOCK` right after the fd exists. (`helper.cr` does the same for the
    # custom Crystal helper socket.)
    #
    # :nodoc:
    def self.force_blocking(handle : LibCasper::CapChannel) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        fd = LibCasper.cap_sock(handle)
        Crystal::System::Socket.set_blocking(fd, true) if fd >= 0
      {% end %}
    end

    # Duplicate this channel. The clone shares limits but has an independent
    # reference count. Equivalent to `cap_clone(3)`.
    def clone : Channel
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        h = LibCasper.cap_clone(@handle)
        raise ::FreeBSD::Capsicum::Error.from_errno("cap_clone") if h.null?
        Channel.new(h)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Close the channel and release its resources. Safe to call multiple times.
    def close : Nil
      return if @closed
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibCasper.cap_close(@handle)
      {% end %}
      @closed = true
    end

    # True if the channel has been closed.
    def closed? : Bool
      @closed
    end

    def to_unsafe : LibCasper::CapChannel
      @handle
    end

    def finalize
      close
    end

    private def check_open!
      raise ::FreeBSD::Capsicum::Error.new("channel is closed") if @closed
    end
  end
end
