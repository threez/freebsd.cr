module FreeBSD::NVList
  # Reads keys from an nvlist received from `cap_recv_nvlist` or
  # `cap_xfer_nvlist`. Does NOT own the pointer — the caller is responsible
  # for lifetime management (the kernel owns received nvlists; do not destroy).
  #
  # ```
  # require "freebsd/nvlist"
  #
  # pull = FreeBSD::NVList::PullParser.new(raw_nvlist_ptr)
  # name = pull.read_string("name")
  # count = pull.read_number("count")
  # ```
  class PullParser
    def initialize(@nvl : LibNv::Nvlist)
    end

    # True if the given key exists in the nvlist.
    def exists?(key : String) : Bool
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_exists(@nvl, key)
      {% else %}
        false
      {% end %}
    end

    # Read a boolean value. Raises `KeyError` if the key is absent.
    def read_bool(key : String) : Bool
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        raise KeyError.new("nvlist key not found: #{key}") unless exists?(key)
        LibNv.nvlist_get_bool(@nvl, key)
      {% else %}
        raise FreeBSD::NVList::UnsupportedPlatformError.new
      {% end %}
    end

    # Read an unsigned 64-bit integer. Raises `KeyError` if absent.
    def read_number(key : String) : UInt64
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        raise KeyError.new("nvlist key not found: #{key}") unless exists?(key)
        LibNv.nvlist_get_number(@nvl, key)
      {% else %}
        raise FreeBSD::NVList::UnsupportedPlatformError.new
      {% end %}
    end

    # Read a string. Raises `KeyError` if absent.
    def read_string(key : String) : String
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        raise KeyError.new("nvlist key not found: #{key}") unless exists?(key)
        String.new(LibNv.nvlist_get_string(@nvl, key))
      {% else %}
        raise FreeBSD::NVList::UnsupportedPlatformError.new
      {% end %}
    end

    # Read a binary value (returns a copy of the bytes). Raises `KeyError` if absent.
    def read_binary(key : String) : Bytes
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        raise KeyError.new("nvlist key not found: #{key}") unless exists?(key)
        size = LibC::SizeT.new(0)
        ptr = LibNv.nvlist_get_binary(@nvl, key, pointerof(size))
        Bytes.new(ptr.as(UInt8*), size).dup
      {% else %}
        raise FreeBSD::NVList::UnsupportedPlatformError.new
      {% end %}
    end

    # Read a nested nvlist as a new (non-owning) `PullParser`.
    # Raises `KeyError` if absent.
    def read_nvlist(key : String) : PullParser
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        raise KeyError.new("nvlist key not found: #{key}") unless exists?(key)
        PullParser.new(LibNv.nvlist_get_nvlist(@nvl, key))
      {% else %}
        raise FreeBSD::NVList::UnsupportedPlatformError.new
      {% end %}
    end

    # Optional readers — return nil if the key is absent.
    def read_bool?(key : String) : Bool?
      exists?(key) ? read_bool(key) : nil
    end

    def read_number?(key : String) : UInt64?
      exists?(key) ? read_number(key) : nil
    end

    def read_string?(key : String) : String?
      exists?(key) ? read_string(key) : nil
    end

    def read_binary?(key : String) : Bytes?
      exists?(key) ? read_binary(key) : nil
    end

    def read_nvlist?(key : String) : PullParser?
      exists?(key) ? read_nvlist(key) : nil
    end

    # Returns the raw pointer. Useful for passing to C functions.
    def to_unsafe : LibNv::Nvlist
      @nvl
    end
  end
end
