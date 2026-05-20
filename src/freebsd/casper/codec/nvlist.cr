require "../../nvlist"

module FreeBSD::Casper
  module Codec
    # Default Helper codec: nvlist via `NVList::Serializable` and `libnv`
    # pack/unpack for the on-wire byte representation.
    #
    # A codec is any module implementing:
    #   `def self.encode(value) : Bytes`
    #   `def self.decode(bytes : Bytes, type : T.class) : T forall T`
    #
    # Request and response types must include `FreeBSD::NVList::Serializable`.
    module NVList
      def self.encode(value) : Bytes
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          builder = ::FreeBSD::NVList::Builder.new
          value.to_nvlist_fields(builder)
          size = LibC::SizeT.new(0)
          ptr = LibNv.nvlist_pack(builder.to_unsafe, pointerof(size))
          raise RuntimeError.new("nvlist_pack failed") if ptr.null?
          # Copy into a Crystal-managed Bytes; free the malloc'd buffer.
          buf = Bytes.new(ptr.as(UInt8*), size).dup
          LibC.free(ptr)
          buf
        {% else %}
          raise ::FreeBSD::NVList::UnsupportedPlatformError.new
        {% end %}
      end

      def self.decode(bytes : Bytes, type : T.class) : T forall T
        {% if flag?(:freebsd) || flag?(:dragonfly) %}
          nvl = LibNv.nvlist_unpack(bytes.to_unsafe, bytes.size, 0)
          raise RuntimeError.new("nvlist_unpack failed") if nvl.null?
          begin
            T.new(::FreeBSD::NVList::PullParser.new(nvl))
          ensure
            LibNv.nvlist_destroy(nvl)
          end
        {% else %}
          raise ::FreeBSD::NVList::UnsupportedPlatformError.new
        {% end %}
      end
    end
  end
end
