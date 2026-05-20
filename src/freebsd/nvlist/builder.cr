module FreeBSD::NVList
  # Builds an nvlist for passing to `cap_send_nvlist` or `cap_limit_set`.
  #
  # The caller owns the underlying `LibNv::Nvlist` pointer until it is
  # transferred to the kernel (at which point the kernel takes ownership and
  # the pointer must not be used again). Call `#close` to free it if you
  # abandon the builder without sending.
  #
  # ```
  # require "freebsd/nvlist"
  #
  # builder = FreeBSD::NVList::Builder.new
  # builder.string("key", "value")
  # builder.number("count", 42_u64)
  # ptr = builder.to_unsafe # pass to LibCasper.cap_send_nvlist / cap_limit_set
  # ```
  class Builder
    @nvl : LibNv::Nvlist
    @closed = false

    def initialize(flags : Int32 = 0)
      @nvl = Pointer(Void).null.as(LibNv::Nvlist)
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        nvl = LibNv.nvlist_create(flags)
        raise RuntimeError.new("nvlist_create failed") if nvl.null?
        @nvl = nvl
      {% end %}
    end

    # Add a null-valued key.
    def null(key : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_add_null(@nvl, key)
      {% end %}
    end

    # Add a boolean key.
    def bool(key : String, value : Bool) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_add_bool(@nvl, key, value)
      {% end %}
    end

    # Add an unsigned 64-bit integer key.
    def number(key : String, value : UInt64) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_add_number(@nvl, key, value)
      {% end %}
    end

    # Add a string key.
    def string(key : String, value : String) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_add_string(@nvl, key, value)
      {% end %}
    end

    # Add a binary (byte slice) key.
    def binary(key : String, value : Bytes) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_add_binary(@nvl, key, value.to_unsafe, value.size)
      {% end %}
    end

    # Add a nested nvlist built by the given block. The child builder is
    # owned by `self` after this call — do not call `#close` on it.
    def nvlist(key : String, & : Builder ->) : Nil
      child = Builder.new
      yield child
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        # nvlist_move_nvlist transfers ownership; child pointer must not be
        # used or destroyed afterwards.
        LibNv.nvlist_move_nvlist(@nvl, key, child.to_unsafe)
        child.transfer!
      {% end %}
    end

    # Dispatch encoder — accepts any value whose type implements
    # `#to_nvlist(builder : FreeBSD::NVList::Builder, key : String)`.
    # Primitives are handled by the overloads in `to_nvlist.cr`.
    def field(key : String, value : Nil) : Nil
      null(key)
    end

    def field(key : String, value : Bool) : Nil
      bool(key, value)
    end

    def field(key : String, value : Int8 | Int16 | Int32 | Int64 |
                                    UInt8 | UInt16 | UInt32 | UInt64) : Nil
      number(key, value.to_u64)
    end

    def field(key : String, value : String) : Nil
      string(key, value)
    end

    def field(key : String, value : Bytes) : Nil
      binary(key, value)
    end

    # Catch-all: delegate to the value's own `#to_nvlist` (covers structs
    # that include `FreeBSD::NVList::Serializable`, `Array`, `Hash`, etc.).
    def field(key : String, value) : Nil
      value.to_nvlist(self, key)
    end

    # Returns the raw nvlist pointer. After transferring ownership to the
    # kernel (e.g. via `cap_send_nvlist`) do NOT call `#close`.
    def to_unsafe : LibNv::Nvlist
      @nvl
    end

    protected def transfer! : Nil
      @closed = true
    end

    # Destroy the nvlist if it has not already been transferred.
    def close : Nil
      return if @closed
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibNv.nvlist_destroy(@nvl)
      {% end %}
      @closed = true
    end

    def finalize
      close
    end
  end
end
