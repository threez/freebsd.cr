# Minimal `libsqlite3` bindings for the VFS *system-call override* API, used by
# `freebsd/capsicum/integrate/sqlite` to redirect SQLite's file opens through
# `openat(2)` beneath a pre-opened directory fd in capability mode.
#
# We bind only what the syscall-override mechanism needs: `sqlite3_vfs_find`,
# the leading fields of `struct sqlite3_vfs` up to and including
# `xSetSystemCall`/`xGetSystemCall`, and the fixed-arity callback signatures for
# the path-taking syscalls we replace. We deliberately do **not** bind the
# SQLite query API — clients bring their own `crystal-sqlite3`/`db` shard; this
# file links `libsqlite3` purely to reach the VFS.
#
# `libsqlite3` is not in base; it ships via the `sqlite3` package (the same
# library `crystal-sqlite3` links). On unsupported platforms this file declares
# an empty namespace so the rest of the shard still compiles.

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("sqlite3")]
  lib LibSQLite3
    # `typedef void (*sqlite3_syscall_ptr)(void);` — the single generic pointer
    # type every overridable syscall is stored as. The unix VFS casts it back to
    # a concrete, *fixed-arity* signature before calling (see the aliases below),
    # which is exactly why these overrides are expressible without variadic
    # callbacks.
    alias SyscallPtr = Void* -> Void

    # The VFS object. Only the fields up to `xSetSystemCall`/`xGetSystemCall`
    # matter to us; every function-pointer field we never call is modelled as a
    # `Void*` (pointer-sized) so the two we *do* call land at the right offset.
    # Field order and types mirror `struct sqlite3_vfs` in sqlite3.h (iVersion 3).
    struct Vfs
      i_version : Int32            # int iVersion
      sz_os_file : Int32           # int szOsFile
      mx_pathname : Int32          # int mxPathname
      p_next : Vfs*                # sqlite3_vfs *pNext
      z_name : LibC::Char*         # const char *zName
      p_app_data : Void*           # void *pAppData
      x_open : Void*               # xOpen
      x_delete : Void*             # xDelete
      x_access : Void*             # xAccess
      x_full_pathname : Void*      # xFullPathname
      x_dl_open : Void*            # xDlOpen
      x_dl_error : Void*           # xDlError
      x_dl_sym : Void*             # xDlSym
      x_dl_close : Void*           # xDlClose
      x_randomness : Void*         # xRandomness
      x_sleep : Void*              # xSleep
      x_current_time : Void*       # xCurrentTime
      x_get_last_error : Void*     # xGetLastError
      x_current_time_int64 : Void* # xCurrentTimeInt64 (v2)
      # v3 — the system-call override interface:
      x_set_system_call : (Vfs*, LibC::Char*, SyscallPtr) -> Int32
      x_get_system_call : (Vfs*, LibC::Char*) -> SyscallPtr
      x_next_system_call : Void* # xNextSystemCall
    end

    # Return the registered VFS named `z_name`, or the default VFS when `z_name`
    # is null. The default unix VFS is named "unix".
    fun sqlite3_vfs_find(z_name : LibC::Char*) : Vfs*

    # ---- fixed-arity syscall signatures we install (all non-variadic) --------
    #
    # These mirror the concrete casts the unix VFS applies in os_unix.c before
    # invoking each overridden entry. `mode_t` is passed as a plain `int` to
    # `posixOpen` (SQLite's own fixed-arity wrapper around libc's variadic
    # `open`), so even "open" is a fixed 3-arg signature here.
    alias OpenFn = (LibC::Char*, Int32, Int32) -> Int32
    alias AccessFn = (LibC::Char*, Int32) -> Int32
    alias StatFn = (LibC::Char*, LibC::Stat*) -> Int32
    alias UnlinkFn = (LibC::Char*) -> Int32
    # int openDirectory(const char *zPath, int *pFd)
    alias OpenDirectoryFn = (LibC::Char*, Int32*) -> Int32
  end
{% else %}
  lib LibSQLite3
    alias SyscallPtr = Void* -> Void

    struct Vfs
      i_version : Int32
    end
  end
{% end %}
