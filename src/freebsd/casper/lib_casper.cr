# Low-level bindings to libcasper.so — the core service-channel API.
#
# Service-specific entry points (libcap_dns, libcap_pwd, ...) live in their
# own lib_*.cr files.

require "../nvlist/lib_nv"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("casper")]
  lib LibCasper
    type CapChannel = Void*

    fun cap_init : CapChannel
    fun cap_close(chan : CapChannel) : Void
    fun cap_clone(chan : CapChannel) : CapChannel
    fun cap_sock(chan : CapChannel) : Int32

    fun cap_service_open(chan : CapChannel, name : LibC::Char*) : CapChannel
    fun cap_service_limit(chan : CapChannel, names : LibC::Char**, nnames : LibC::SizeT) : Int32

    fun cap_limit_get(chan : CapChannel, limits : LibNv::Nvlist*) : Int32
    fun cap_limit_set(chan : CapChannel, limits : LibNv::Nvlist) : Int32

    fun cap_send_nvlist(chan : CapChannel, nvl : LibNv::Nvlist) : Int32
    fun cap_recv_nvlist(chan : CapChannel) : LibNv::Nvlist
    fun cap_xfer_nvlist(chan : CapChannel, nvl : LibNv::Nvlist) : LibNv::Nvlist
  end
{% else %}
  lib LibCasper
    type CapChannel = Void*
  end
{% end %}
