require "../casper"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_sysctl")]
  lib LibCapSysctl
    CAP_SYSCTL_READ      = 1
    CAP_SYSCTL_WRITE     = 2
    CAP_SYSCTL_RDWR      = (CAP_SYSCTL_READ | CAP_SYSCTL_WRITE)
    CAP_SYSCTL_RECURSIVE = 4

    fun cap_sysctlbyname(chan : LibCasper::CapChannel,
                         name : LibC::Char*,
                         oldp : Void*, oldlenp : LibC::SizeT*,
                         newp : Void*, newlen : LibC::SizeT) : Int32

    fun cap_sysctl_limit_init(chan : LibCasper::CapChannel) : Void*
    fun cap_sysctl_limit_name(limit : Void*, name : LibC::Char*, flags : Int32) : Void*
    fun cap_sysctl_limit(limit : Void*) : Int32
  end
{% end %}

module FreeBSD::Casper
  class Service::Sysctl < Service
    # Permission mask for `#limit`. Controls which operations are allowed on
    # each name. `Recursive` applies the rule to the entire subtree under a prefix.
    @[Flags]
    enum Mode : Int32
      Read      = 1
      Write     = 2
      ReadWrite = 3
      Recursive = 4
    end

    # Fetch a sysctl as a raw byte buffer. Caller decodes into the expected
    # native type. Returns the bytes that were actually written by the helper.
    def get_bytes(name : String, max_size : Int32 = 4096) : Bytes
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        buf = Bytes.new(max_size)
        oldlen = max_size.to_u64
        rc = LibCapSysctl.cap_sysctlbyname(@handle, name,
          buf.to_unsafe.as(Void*), pointerof(oldlen),
          Pointer(Void).null, 0_u64)
        if rc != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_sysctlbyname(#{name}) get")
        end
        buf[0, oldlen]
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Fetch a sysctl as a UTF-8 string. Trailing NUL is trimmed.
    def get_string(name : String, max_size : Int32 = 4096) : String
      bytes = get_bytes(name, max_size)
      bytes = bytes[0, bytes.size - 1] if bytes.size > 0 && bytes[-1] == 0_u8
      String.new(bytes)
    end

    # Fetch a sysctl as an Int32.
    def get_i32(name : String) : Int32
      bytes = get_bytes(name, 4)
      raise ::FreeBSD::Capsicum::Error.new("sysctl #{name}: expected 4 bytes, got #{bytes.size}") if bytes.size != 4
      bytes.to_unsafe.as(Int32*).value
    end

    # Set a sysctl from raw bytes. The caller is responsible for correct
    # endianness and size for the target sysctl type.
    def set_bytes(name : String, value : Bytes) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        rc = LibCapSysctl.cap_sysctlbyname(@handle, name,
          Pointer(Void).null, Pointer(LibC::SizeT).null,
          value.to_unsafe.as(Void*), value.size.to_u64)
        if rc != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_sysctlbyname(#{name}) set")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Limit the set of sysctl names that may be queried, with a mode per name.
    # `entries` maps a sysctl name (or prefix when `mode` includes Recursive)
    # to its allowed access mode.
    def limit(entries : Hash(String, Mode)) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        limit = LibCapSysctl.cap_sysctl_limit_init(@handle)
        raise ::FreeBSD::Capsicum::Error.from_errno("cap_sysctl_limit_init") if limit.null?
        entries.each do |name, mode|
          limit = LibCapSysctl.cap_sysctl_limit_name(limit, name, mode.value)
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_sysctl_limit_name(#{name})") if limit.null?
        end
        if LibCapSysctl.cap_sysctl_limit(limit) != 0
          raise ::FreeBSD::Capsicum::Error.from_errno("cap_sysctl_limit")
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end
  end

  class Channel
    # Open the `system.sysctl` Casper service on this channel.
    def sysctl : Service::Sysctl
      Service::Sysctl.new(service("system.sysctl"))
    end
  end
end
