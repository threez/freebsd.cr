# Low-level bindings to FreeBSD Capsicum, exported from libc.
#
# Capsicum lives in libc on FreeBSD (no extra -l flag). On unsupported
# platforms this file declares an empty namespace so the rest of the shard
# still compiles; public methods will raise `Casper::UnsupportedPlatformError`.

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("c")]
  lib LibCapsicum
    CAP_RIGHTS_VERSION = 0

    # struct cap_rights { uint64_t cr_rights[2]; }
    struct CapRights
      cr_rights : UInt64[2]
    end

    # ---- capability mode ------------------------------------------------------

    fun cap_enter : Int32
    fun cap_getmode(modep : UInt32*) : Int32
    fun cap_sandboxed : Bool

    # ---- rights ---------------------------------------------------------------

    # Variadic C functions; each right is a UInt64 and the list is terminated
    # with 0_u64.
    fun __cap_rights_init(version : Int32, rights : CapRights*, ...) : CapRights*
    fun __cap_rights_set(rights : CapRights*, ...) : CapRights*
    fun __cap_rights_clear(rights : CapRights*, ...) : CapRights*
    fun __cap_rights_is_set(rights : CapRights*, ...) : Bool

    fun cap_rights_is_valid(rights : CapRights*) : Bool
    fun cap_rights_merge(dst : CapRights*, src : CapRights*) : CapRights*
    fun cap_rights_remove(dst : CapRights*, src : CapRights*) : CapRights*
    fun cap_rights_contains(big : CapRights*, little : CapRights*) : Bool

    fun cap_rights_limit(fd : Int32, rights : CapRights*) : Int32
    fun __cap_rights_get(version : Int32, fd : Int32, rights : CapRights*) : Int32

    # ---- ioctl / fcntl limits -------------------------------------------------

    fun cap_ioctls_limit(fd : Int32, cmds : LibC::ULong*, ncmds : LibC::SizeT) : Int32
    fun cap_ioctls_get(fd : Int32, cmds : LibC::ULong*, maxcmds : LibC::SizeT) : Int32

    fun cap_fcntls_limit(fd : Int32, fcntlrights : UInt32) : Int32
    fun cap_fcntls_get(fd : Int32, fcntlrightsp : UInt32*) : Int32
  end
{% else %}
  lib LibCapsicum
    CAP_RIGHTS_VERSION = 0

    struct CapRights
      cr_rights : UInt64[2]
    end
  end
{% end %}
