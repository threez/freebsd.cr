module FreeBSD::Casper
  # Base class for a Casper service handle. Each subclass wraps the channel
  # returned by `cap_service_open` and exposes service-specific operations.
  abstract class Service
    @handle : LibCasper::CapChannel
    @closed = false

    def initialize(@handle : LibCasper::CapChannel)
    end

    # Returns the underlying `cap_channel_t*`. Used by C FFI call sites.
    def to_unsafe : LibCasper::CapChannel
      @handle
    end

    # Close the service channel. Safe to call multiple times.
    def close : Nil
      return if @closed
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibCasper.cap_close(@handle)
      {% end %}
      @closed = true
    end

    # True if the service has been closed.
    def closed? : Bool
      @closed
    end

    def finalize
      close
    end

    protected def check_open!
      raise ::FreeBSD::Capsicum::Error.new("service is closed") if @closed
    end
  end
end
