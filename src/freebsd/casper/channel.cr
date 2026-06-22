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
        svc
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
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
