# Route `libsqlite3`'s file opens through `openat(2)` beneath a registered
# `Directory`, so a SQLite database — including a **WAL** database, which lazily
# creates and opens `-wal` and `-shm` sidecars *after* the first transaction —
# reads and writes entirely inside a Capsicum sandbox.
#
# ## Why this is needed
#
# `libsqlite3` opens its files with its own `open(2)` inside the unix VFS; those
# opens never pass through `Crystal::System::File.open`, so the `integrate/file`
# routing does not catch them. In capability mode `open(2)` is forbidden
# (`ECAPMODE`), and pre-opening the main db fd is not enough: the `-wal`/`-shm`
# files are opened on the first transaction, already inside the sandbox.
#
# SQLite's unix VFS exposes `xSetSystemCall` precisely so a sandbox can swap the
# individual path-taking syscalls while the stock VFS keeps doing all locking,
# mmap, and flag handling. We replace the five path-taking syscalls SQLite uses
# for a WAL database — `open`, `access`, `stat`, `lstat`, `unlink` — plus
# `openDirectory` (the parent-dir fsync), redirecting each to its `*at` form
# beneath the registered directory fd. Everything after open (reads, writes,
# byte-range locks, the `-shm` mmap) operates on the returned fd and is left
# untouched.
#
# ## Usage
#
# ```
# require "freebsd/capsicum/integrate/sqlite"
#
# # Open /var/data with the rights a WAL db needs, register it, and install the
# # VFS override — all in one call, BEFORE cap_enter.
# FreeBSD::Capsicum.register_sqlite_dir("/var/data")
# FreeBSD::Capsicum.sandbox!
#
# db = DB.open("sqlite3:///var/data/app.db") # absolute path — see below
# db.exec "PRAGMA journal_mode=WAL"
# db.exec "CREATE TABLE IF NOT EXISTS t (n INTEGER)"
# db.exec "INSERT INTO t VALUES (?)", 42
# ```
#
# `register_sqlite_dir` returns the `Directory` if you need to list or close it.
# To wire the steps yourself (e.g. custom rights handling), the lower-level
# `Directory.open` + `register_directory` + `install_sqlite_vfs_openat` remain
# available; `register_sqlite_dir` just bundles them with `SQLITE_WAL_RIGHTS`.
#
# ## Requirements and caveats
#
#   * **Install + register before `sandbox!`.** `install_sqlite_vfs_openat`
#     mutates the process-global default unix VFS in place; do it (and
#     `register_directory`) before entering capability mode and before opening
#     any connection.
#   * **Use an absolute db path.** SQLite calls `getcwd(2)` to resolve a relative
#     name; `getcwd` is forbidden in capability mode. An absolute path is
#     resolved lexically by `directory_for` and never hits `getcwd`.
#   * **`/dev/null` and `/dev/urandom`** are opened by SQLite by absolute path
#     (fd-exhaustion fallback and `xRandomness`). They match no registered
#     directory and so fall through to the original syscall — which still works
#     in the sandbox only if those device fds are otherwise reachable; SQLite
#     tolerates their failure. No special handling is required here.
#   * **Directory rights.** The dir fd must carry at least `:lookup, :read,
#     :write, :create, :fstat, :fcntl, :seek, :flock, :mmap, :fsync,
#     :ftruncate, :unlinkat` for a read+write WAL database. `:fsync` is easy to
#     miss: SQLite fsyncs the db and journal on commit, and a child fd opened
#     beneath the dir fd inherits its rights, so omitting `:fsync` surfaces as a
#     `SQLite3::Exception: disk I/O error` — even outside capability mode, since
#     Capsicum rights are enforced on the fd regardless. See `Directory.open`.
#
# Paths not beneath any registered directory fall through to SQLite's original
# syscall unchanged, so installing this is safe even for databases outside a
# sandboxed directory.

require "../directory"
require "../lib_sqlite3"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  module FreeBSD::Capsicum
    # The Capsicum rights a directory fd must carry for a read+write WAL SQLite
    # database opened beneath it. The default for `register_sqlite_dir`. Each
    # right maps to a concrete SQLite operation:
    #
    #   :lookup    — openat path traversal
    #   :read/:write/:create — open the db/-wal/-shm for r/w and create them
    #   :fstat     — stat/lstat and fd setup
    #   :fcntl     — byte-range locks (F_SETLK/F_GETLK) on the -shm/-wal fds
    #   :seek      — buffered/positioned IO
    #   :flock     — advisory locking
    #   :mmap      — the -shm shared-memory mapping
    #   :fsync     — fsync of the db and journal on commit (omitting this is the
    #                classic "disk I/O error" trap — child fds inherit dir rights)
    #   :ftruncate — WAL checkpoint truncation
    #   :unlinkat  — removing -wal/-shm at checkpoint/close
    SQLITE_WAL_RIGHTS = [
      :lookup, :read, :write, :create, :fstat, :fcntl,
      :seek, :flock, :mmap, :fsync, :ftruncate, :unlinkat,
    ] of Symbol | Capability::Right

    # Open `path` as a `Directory` with the rights a read+write WAL database
    # needs, register it for `openat` routing, and install the SQLite VFS
    # override — the three steps every sandboxed-SQLite program must run before
    # `cap_enter`, bundled into one call. Returns the `Directory` so the caller
    # can list/close/inspect it.
    #
    # ```
    # dir = FreeBSD::Capsicum.register_sqlite_dir("/var/data")
    # FreeBSD::Capsicum.sandbox!
    # DB.open("sqlite3:///var/data/app.db") { |db| ... }
    # ```
    #
    # Pass `rights:` to override `SQLITE_WAL_RIGHTS` (e.g. a read-only database
    # needs far fewer). `exact_rights: true` applies them verbatim without the
    # `Directory.open` union — see `Directory.open`. Safe to call for several
    # directories: `install_sqlite_vfs_openat` is idempotent, so the VFS override
    # is installed once and each directory is registered.
    def self.register_sqlite_dir(path : String,
                                 rights : Enumerable(Symbol | Capability::Right) = SQLITE_WAL_RIGHTS,
                                 exact_rights : Bool = false) : Directory
      dir = Directory.open(path, rights: rights, exact_rights: exact_rights)
      register_directory(dir)
      install_sqlite_vfs_openat
      dir
    end

    # GC-stable storage for the original (pre-override) syscall pointers, so each
    # override can delegate to the real implementation for paths that do not
    # match a registered directory. Keyed by syscall name.
    @@sqlite_orig = {} of String => LibSQLite3::SyscallPtr

    # The installed C callbacks, kept at class scope so the GC never collects the
    # closures while SQLite holds raw pointers to them.
    @@sqlite_open_cb : LibSQLite3::OpenFn?
    @@sqlite_access_cb : LibSQLite3::AccessFn?
    @@sqlite_stat_cb : LibSQLite3::StatFn?
    @@sqlite_lstat_cb : LibSQLite3::StatFn?
    @@sqlite_unlink_cb : LibSQLite3::UnlinkFn?
    @@sqlite_opendir_cb : LibSQLite3::OpenDirectoryFn?

    # True once `install_sqlite_vfs_openat` has run. Installing is idempotent.
    @@sqlite_vfs_installed = false

    # :nodoc:
    # Set `errno` and return the conventional failure value for a syscall that
    # returns an int (-1) — used when a relative path reaches an override (it
    # cannot be resolved without `getcwd`, which is unavailable here).
    private def self.sqlite_fail_relative : Int32
      # ECAPMODE is not in Crystal's `Errno` enum (see capsicum/errors.cr); build
      # it from the raw value so SQLite sees a capability-mode failure.
      Errno.value = Errno.new(ECAPMODE)
      -1
    end

    # Install the `openat`-based VFS syscall overrides onto the default unix VFS.
    # Idempotent. Call once, before opening any connection and before `sandbox!`.
    #
    # Raises `Error` if the default VFS cannot be found or is too old to support
    # the system-call interface (`iVersion < 3`).
    def self.install_sqlite_vfs_openat : Nil
      return if @@sqlite_vfs_installed

      vfs = LibSQLite3.sqlite3_vfs_find(Pointer(LibC::Char).null)
      raise Error.new("sqlite3_vfs_find returned null (no default VFS)") if vfs.null?
      if vfs.value.i_version < 3
        raise Error.new("default sqlite VFS iVersion #{vfs.value.i_version} < 3; no xSetSystemCall")
      end

      build_sqlite_callbacks
      install_one(vfs, "open", @@sqlite_open_cb.not_nil!)
      install_one(vfs, "access", @@sqlite_access_cb.not_nil!)
      install_one(vfs, "stat", @@sqlite_stat_cb.not_nil!)
      install_one(vfs, "lstat", @@sqlite_lstat_cb.not_nil!)
      install_one(vfs, "unlink", @@sqlite_unlink_cb.not_nil!)
      install_one(vfs, "openDirectory", @@sqlite_opendir_cb.not_nil!)

      @@sqlite_vfs_installed = true
    end

    # :nodoc:
    # Capture the original pointer for `name` (for delegation), then install
    # `cb` as the replacement. `cb` is reinterpreted to the generic
    # `SyscallPtr` the VFS stores.
    private def self.install_one(vfs : LibSQLite3::Vfs*, name : String, cb) : Nil
      cname = name.to_unsafe
      orig = vfs.value.x_get_system_call.call(vfs, cname)
      @@sqlite_orig[name] = orig
      # Reinterpret our concrete callback as the generic SyscallPtr the VFS
      # stores: same code address, different (erased) signature. A C function
      # pointer carries no closure data, so the closure pointer is null.
      ptr = LibSQLite3::SyscallPtr.new(cb.pointer.as(Void*), Pointer(Void).null)
      if vfs.value.x_set_system_call.call(vfs, cname, ptr) != 0
        raise Error.new("xSetSystemCall(#{name}) failed")
      end
    end

    # :nodoc:
    # The saved original syscall pointer for `key`, reinterpreted to a concrete
    # function type, or nil if none was captured. The `SyscallPtr` we stored is
    # the same address SQLite handed us; we only change how it's typed to call.
    private def self.sqlite_orig_open(key : String) : LibSQLite3::OpenFn?
      (o = @@sqlite_orig[key]?) ? LibSQLite3::OpenFn.new(o.pointer.as(Void*), Pointer(Void).null) : nil
    end

    private def self.sqlite_orig_access(key : String) : LibSQLite3::AccessFn?
      (o = @@sqlite_orig[key]?) ? LibSQLite3::AccessFn.new(o.pointer.as(Void*), Pointer(Void).null) : nil
    end

    private def self.sqlite_orig_stat(key : String) : LibSQLite3::StatFn?
      (o = @@sqlite_orig[key]?) ? LibSQLite3::StatFn.new(o.pointer.as(Void*), Pointer(Void).null) : nil
    end

    private def self.sqlite_orig_unlink(key : String) : LibSQLite3::UnlinkFn?
      (o = @@sqlite_orig[key]?) ? LibSQLite3::UnlinkFn.new(o.pointer.as(Void*), Pointer(Void).null) : nil
    end

    private def self.sqlite_orig_opendir(key : String) : LibSQLite3::OpenDirectoryFn?
      (o = @@sqlite_orig[key]?) ? LibSQLite3::OpenDirectoryFn.new(o.pointer.as(Void*), Pointer(Void).null) : nil
    end

    # :nodoc:
    # Build the GC-stable C callbacks. Each resolves its path argument against
    # the directory registry: a match is served via the corresponding `*at`
    # syscall beneath the directory fd; anything else delegates to the original
    # syscall captured at install time.
    private def self.build_sqlite_callbacks : Nil
      @@sqlite_open_cb = LibSQLite3::OpenFn.new do |path, flags, mode|
        rel = sqlite_resolve(path)
        if rel
          dir, relpath = rel
          # Force confinement beneath the dir fd; SQLite already supplies the
          # O_RDONLY/O_RDWR/O_CREAT/... mode bits in `flags`.
          LibOpenat.openat(dir.fd, relpath, flags | LibOpenat::O_RESOLVE_BENEATH, LibC::ModeT.new(mode))
        elsif orig = sqlite_orig_open("open")
          orig.call(path, flags, mode)
        else
          sqlite_fail_relative
        end
      end

      @@sqlite_access_cb = LibSQLite3::AccessFn.new do |path, mode|
        rel = sqlite_resolve(path)
        if rel
          dir, relpath = rel
          LibOpenat.faccessat(dir.fd, relpath, mode, LibOpenat::AT_RESOLVE_BENEATH)
        elsif orig = sqlite_orig_access("access")
          orig.call(path, mode)
        else
          sqlite_fail_relative
        end
      end

      @@sqlite_stat_cb = LibSQLite3::StatFn.new do |path, sb|
        sqlite_stat(path, sb, LibOpenat::AT_RESOLVE_BENEATH, "stat")
      end

      @@sqlite_lstat_cb = LibSQLite3::StatFn.new do |path, sb|
        sqlite_stat(path, sb, LibOpenat::AT_RESOLVE_BENEATH | LibOpenat::AT_SYMLINK_NOFOLLOW, "lstat")
      end

      @@sqlite_unlink_cb = LibSQLite3::UnlinkFn.new do |path|
        rel = sqlite_resolve(path)
        if rel
          dir, relpath = rel
          LibOpenat.unlinkat(dir.fd, relpath, 0)
        elsif orig = sqlite_orig_unlink("unlink")
          orig.call(path)
        else
          sqlite_fail_relative
        end
      end

      # `openDirectory(zPath, *pFd)` opens the *containing* directory for the
      # post-write fsync; for a db at <base>/app.db that path is the registered
      # base itself, so match on base-or-descendant.
      @@sqlite_opendir_cb = LibSQLite3::OpenDirectoryFn.new do |path, p_fd|
        rel = sqlite_resolve_or_base(path)
        if rel
          dir, relpath = rel
          fd = LibOpenat.openat(dir.fd, relpath,
            LibOpenat::O_RDONLY | LibOpenat::O_DIRECTORY |
            LibOpenat::O_RESOLVE_BENEATH | LibC::O_CLOEXEC)
          if fd >= 0
            p_fd.value = fd
            0
          else
            -1
          end
        elsif orig = sqlite_orig_opendir("openDirectory")
          orig.call(path, p_fd)
        else
          sqlite_fail_relative
        end
      end
    end

    # :nodoc:
    # Shared body for the stat/lstat overrides.
    #
    # A path beneath a registered base is stat'd via `fstatat` under the dir fd.
    # Otherwise we'd normally delegate — but SQLite's `xFullPathname` `lstat`s the
    # *ancestor directories* of the db path (e.g. `/tmp`, `/var`) to resolve
    # symlinks, and in capability mode those delegated calls fail with `ECAPMODE`,
    # which makes SQLite abort the open with `SQLITE_CANTOPEN`. For a path that is
    # an ancestor of (or equal to) a registered base we therefore fabricate a
    # "plain directory, not a symlink" result so the symlink-resolution loop
    # terminates without escaping the sandbox. We confine actual file access with
    # `O_RESOLVE_BENEATH` regardless, so faking the ancestor stat is safe. Any
    # other unrelated path still delegates to the original syscall.
    private def self.sqlite_stat(path : LibC::Char*, sb : LibC::Stat*, flag : Int32, name : String) : Int32
      str = String.new(path)
      if rel = directory_for(str)
        dir, relpath = rel
        LibOpenat.fstatat(dir.fd, relpath, sb, flag)
      elsif sqlite_ancestor_of_base?(str)
        sqlite_fake_dir_stat(sb)
      elsif orig = sqlite_orig_stat(name)
        orig.call(path, sb)
      else
        sqlite_fail_relative
      end
    end

    # :nodoc:
    # True if `path` is an ancestor of, or equal to, a registered directory base
    # — i.e. SQLite is walking up the db path during canonicalization.
    private def self.sqlite_ancestor_of_base?(path : String) : Bool
      return false if directories.empty?
      p = ::Path[path].normalize
      directories.each_key do |base|
        bp = ::Path[base]
        return true if bp == p || bp.relative_to?(p).try { |r| !r.parts.includes?("..") && r.to_s != "." }
      end
      false
    end

    # :nodoc:
    # Fill `sb` with a minimal "plain directory, not a symlink" stat and return
    # success (0). Only `st_mode` matters to SQLite's symlink check.
    private def self.sqlite_fake_dir_stat(sb : LibC::Stat*) : Int32
      st = LibC::Stat.new
      st.st_mode = LibC::S_IFDIR | 0o755
      sb.value = st
      0
    end

    # :nodoc:
    # Resolve a C path to `{Directory, relpath}` strictly beneath a registered
    # base, or nil. Mirrors `File.open` routing.
    private def self.sqlite_resolve(path : LibC::Char*) : {Directory, String}?
      directory_for(String.new(path))
    end

    # :nodoc:
    # Like `sqlite_resolve` but also matches a path equal to a registered base
    # (returning `{dir, "."}`) — for `openDirectory` of the db's parent dir.
    private def self.sqlite_resolve_or_base(path : LibC::Char*) : {Directory, String}?
      directory_or_base_for(String.new(path))
    end
  end
{% end %}
