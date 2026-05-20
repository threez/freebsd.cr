{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("nv")]
  lib LibNv
    NV_FLAG_IGNORE_CASE = 0x01
    NV_FLAG_NO_UNIQUE   = 0x02

    type Nvlist = Void*

    # FreeBSD 15 exports nvlist symbols with a "FreeBSD_" prefix; the C header
    # maps them back via #define. We bind the actual symbol names directly.
    @[CallConvention("C")]
    fun nvlist_create = FreeBSD_nvlist_create(flags : Int32) : Nvlist
    fun nvlist_destroy = FreeBSD_nvlist_destroy(nvl : Nvlist) : Void
    fun nvlist_error = FreeBSD_nvlist_error(nvl : Nvlist) : Int32
    fun nvlist_empty = FreeBSD_nvlist_empty(nvl : Nvlist) : Bool
    fun nvlist_exists = FreeBSD_nvlist_exists(nvl : Nvlist, name : LibC::Char*) : Bool
    fun nvlist_exists_type = FreeBSD_nvlist_exists_type(nvl : Nvlist, name : LibC::Char*, type : Int32) : Bool

    fun nvlist_add_null = FreeBSD_nvlist_add_null(nvl : Nvlist, name : LibC::Char*) : Void
    fun nvlist_add_bool = FreeBSD_nvlist_add_bool(nvl : Nvlist, name : LibC::Char*, value : Bool) : Void
    fun nvlist_add_number = FreeBSD_nvlist_add_number(nvl : Nvlist, name : LibC::Char*, value : UInt64) : Void
    fun nvlist_add_string = FreeBSD_nvlist_add_string(nvl : Nvlist, name : LibC::Char*, value : LibC::Char*) : Void
    fun nvlist_add_binary = FreeBSD_nvlist_add_binary(nvl : Nvlist, name : LibC::Char*, value : Void*, size : LibC::SizeT) : Void
    fun nvlist_add_nvlist = FreeBSD_nvlist_add_nvlist(nvl : Nvlist, name : LibC::Char*, value : Nvlist) : Void
    fun nvlist_move_string = FreeBSD_nvlist_move_string(nvl : Nvlist, name : LibC::Char*, value : LibC::Char*) : Void
    fun nvlist_move_nvlist = FreeBSD_nvlist_move_nvlist(nvl : Nvlist, name : LibC::Char*, value : Nvlist) : Void

    fun nvlist_get_bool = FreeBSD_nvlist_get_bool(nvl : Nvlist, name : LibC::Char*) : Bool
    fun nvlist_get_number = FreeBSD_nvlist_get_number(nvl : Nvlist, name : LibC::Char*) : UInt64
    fun nvlist_get_string = FreeBSD_nvlist_get_string(nvl : Nvlist, name : LibC::Char*) : LibC::Char*
    fun nvlist_get_binary = FreeBSD_nvlist_get_binary(nvl : Nvlist, name : LibC::Char*, sizep : LibC::SizeT*) : Void*
    fun nvlist_get_nvlist = FreeBSD_nvlist_get_nvlist(nvl : Nvlist, name : LibC::Char*) : Nvlist

    fun nvlist_take_string = FreeBSD_nvlist_take_string(nvl : Nvlist, name : LibC::Char*) : LibC::Char*
    fun nvlist_take_nvlist = FreeBSD_nvlist_take_nvlist(nvl : Nvlist, name : LibC::Char*) : Nvlist

    fun nvlist_pack = FreeBSD_nvlist_pack(nvl : Nvlist, sizep : LibC::SizeT*) : Void*
    fun nvlist_unpack = FreeBSD_nvlist_unpack(buf : Void*, size : LibC::SizeT, flags : Int32) : Nvlist
  end
{% else %}
  lib LibNv
    type Nvlist = Void*
  end
{% end %}
