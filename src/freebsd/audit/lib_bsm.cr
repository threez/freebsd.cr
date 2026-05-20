require "socket"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("bsm")]
  lib LibBsm
    # Pass to `au_close` to commit the record to the audit trail.
    AU_TO_WRITE = 1

    # Pass to `au_close` to discard the record without writing.
    AU_TO_NO_WRITE = 0

    # Sentinel audit UID meaning "not in an audit session".
    AU_NOAUDITID = 4294967295_u32 # ~0

    # Opaque token type. Never dereference; only pass to `au_write`/`au_free_token`.
    type AuToken = Void*

    # Classic 32-bit terminal ID (IPv4 only).
    #
    # Both fields are `u_int32_t` in FreeBSD's `audit.h` — do NOT use
    # `LibC::DevT` here (which is 64-bit on amd64 and would mis-size the struct).
    struct AuTid
      port : UInt32    # terminal port (0 for daemons)
      machine : UInt32 # IPv4 address of terminal, network byte order
    end

    # Extended terminal ID supporting IPv6 (used by `au_to_subject32_ex`).
    struct AuTidAddr
      at_port : UInt32
      at_type : UInt32    # AU_IPv4 = 4, AU_IPv6 = 16
      at_addr : UInt32[4] # raw address bytes (4 bytes IPv4 or 16 bytes IPv6)
    end

    # -------------------------------------------------------------------------
    # Record lifecycle
    # -------------------------------------------------------------------------

    # Open a new audit record. Returns a descriptor >= 0 on success, -1 on error.
    fun au_open : Int32

    # Write *m* into record *d*. On success (0) libbsm owns *m* — do not free.
    # On failure (-1) *m* is untouched — caller must call `au_free_token`.
    fun au_write(d : Int32, m : AuToken) : Int32

    # Commit (*keep* = `AU_TO_WRITE`) or discard (*keep* = `AU_TO_NO_WRITE`)
    # the record identified by *d*, tagging it with BSM event type *event*.
    fun au_close(d : Int32, keep : Int32, event : UInt16) : Int32

    # -------------------------------------------------------------------------
    # Token constructors
    # -------------------------------------------------------------------------

    # Free a token that was NOT consumed by `au_write` (i.e. `au_write` returned -1).
    fun au_free_token(tok : AuToken) : Void

    # Arbitrary text string token.
    fun au_to_text(text : LibC::Char*) : AuToken

    # Return-value token. *status* 0 = success, 1 = failure.
    fun au_to_return32(status : UInt8, ret : UInt32) : AuToken

    # Subject token (IPv4 / no terminal).
    fun au_to_subject32(
      auid : UInt32, euid : UInt32, egid : UInt32,
      ruid : UInt32, rgid : UInt32,
      pid : Int32, sid : UInt32, tid : AuTid*,
    ) : AuToken

    # Subject token (supports IPv6 terminal address).
    fun au_to_subject32_ex(
      auid : UInt32, euid : UInt32, egid : UInt32,
      ruid : UInt32, rgid : UInt32,
      pid : Int32, sid : UInt32, tid : AuTidAddr*,
    ) : AuToken

    # IPv4 address token. *addr* points to a `LibC::InAddr` (4 bytes).
    fun au_to_in_addr(addr : LibC::InAddr*) : AuToken

    # IPv6 address token. *addr* points to a `LibC::In6Addr` (16 bytes).
    fun au_to_in_addr_ex(addr : LibC::In6Addr*) : AuToken

    # -------------------------------------------------------------------------
    # Helpers (libc functions not exposed by Crystal's stdlib on FreeBSD)
    # -------------------------------------------------------------------------

    # Convert a presentation-format address string to network bytes.
    # Returns 1 on success, 0 if the string is not valid, -1 on error.
    fun inet_pton(af : Int32, src : LibC::Char*, dst : Void*) : Int32

    # Effective UID/GID — Crystal stdlib only binds getuid/getgid on FreeBSD.
    fun geteuid : LibC::UidT
    fun getegid : LibC::GidT
    fun getgid : LibC::GidT
  end
{% else %}
  lib LibBsm
    AU_TO_WRITE    =              1
    AU_TO_NO_WRITE =              0
    AU_NOAUDITID   = 4294967295_u32
  end
{% end %}
