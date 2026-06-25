require "../capsicum"
require "./file_from_fd"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  # The `*at` syscalls and flags Crystal's FreeBSD `LibC` does not expose, used to
  # operate beneath a directory fd in capability mode. All live in libc (no extra
  # link flag). `openat`'s trailing `mode_t` is variadic (only consumed with
  # `O_CREAT`); `fstatat`/`faccessat` take an `AT_*` flag; `fdopendir` adopts the
  # fd it is given.
  @[Link("c")]
  lib LibOpenat
    O_RDONLY          = 0x00000000
    O_DIRECTORY       = 0x00020000
    O_RESOLVE_BENEATH = 0x00800000

    # AT_* flags for the *at calls; AT_RESOLVE_BENEATH confines lookups beneath
    # the starting dir fd (the stat/access analog of O_RESOLVE_BENEATH).
    AT_SYMLINK_NOFOLLOW = 0x0200
    AT_RESOLVE_BENEATH  = 0x2000

    fun openat(fd : Int32, path : LibC::Char*, oflag : Int32, ...) : Int32
    fun fstatat(fd : Int32, path : LibC::Char*, sb : LibC::Stat*, flag : Int32) : Int32
    fun faccessat(fd : Int32, path : LibC::Char*, mode : Int32, flag : Int32) : Int32
    fun unlinkat(fd : Int32, path : LibC::Char*, flag : Int32) : Int32
    fun fdopendir(fd : Int32) : LibC::DIR*
    fun dup(fd : Int32) : Int32
  end
{% end %}

module FreeBSD::Capsicum
  # A directory descriptor opened *before* `cap_enter`, used to open files
  # beneath it via `openat(2)` from inside the sandbox.
  #
  # In capability mode FreeBSD forbids `open(2)`; the only in-process way to open
  # a file is `openat` relative to an already-open directory fd. Open (and
  # optionally rights-limit) the directory up front, carry the fd into the
  # sandbox, then `openat` files beneath it:
  #
  # ```
  # require "freebsd/capsicum/directory"
  #
  # dir = FreeBSD::Capsicum::Directory.open("/var/www", rights: [:lookup, :read, :fstat])
  # FreeBSD::Capsicum.sandbox!
  # dir.open("index.html") { |f| puts f.gets_to_end } # openat under the dir fd
  # ```
  #
  # `relpath` arguments must be relative; absolute paths and `..` escapes are
  # rejected (the latter in-kernel by `O_RESOLVE_BENEATH`). The directory fd
  # needs `:lookup` for traversal plus `:read`/`:write`/`:create` for the
  # corresponding open modes; opened child fds inherit a subset of these rights.
  #
  # Register a `Directory` with `FreeBSD::Capsicum.register_directory` to route
  # `File.open` of paths beneath its base through `openat` transparently — see
  # `freebsd/capsicum/integrate/file`.
  class Directory
    # The normalized absolute path this directory was opened at (no trailing
    # slash). Used as the registry key and for relative-path matching.
    getter base : String

    # The directory file descriptor.
    getter fd : Int32

    @closed = false

    protected def initialize(@base : String, @fd : Int32)
    end

    # Open `path` as a directory descriptor. Runs *before* `cap_enter`, so it
    # uses `open(2)` (`O_DIRECTORY | O_CLOEXEC`). When `rights:` is given the fd
    # is immediately limited via `cap_rights_limit`.
    #
    # By default the listed rights are *unioned* with the rights the directory fd
    # needs for `openat` and for Crystal's file/IO machinery, so the wrapped
    # children Just Work:
    #
    #   * `:lookup`        — path traversal (`openat` itself)
    #   * `:fcntl, :fstat` — Crystal's `File`/`IO` setup calls `fcntl(F_GETFL)`
    #                        and `fstat` when wrapping an opened fd; without these
    #                        the child fd reads as a closed stream (`ENOTCAPABLE`)
    #   * `:seek`          — buffered `File` IO repositions the child fd
    #
    # `:fstat` + `:lookup` also satisfy `info?`/`exists?`; `:read` + `:lookup` +
    # `:fstat` satisfy `entries`/`children`/`each_child`.
    #
    # Pass `exact_rights: true` to skip the union and apply *exactly* the listed
    # rights — an advanced escape hatch for a minimal fd. The caller is then
    # responsible for including whatever the operations they use require (e.g.
    # `:fcntl, :fstat, :seek` for `open`/`open_io`). `exact_rights: true` with no
    # `rights:` raises `ArgumentError`.
    def self.open(path : String,
                  rights : Enumerable(Symbol | Capability::Right)? = nil,
                  exact_rights : Bool = false) : Directory
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        if exact_rights && rights.nil?
          raise ArgumentError.new("exact_rights: true requires an explicit rights: list")
        end

        base = ::Path[path].expand.to_s
        fd = LibC.open(base, LibOpenat::O_DIRECTORY | LibC::O_CLOEXEC)
        if fd < 0
          raise ::File::Error.from_errno("open directory", file: path)
        end

        dir = new(base, fd)
        if rights
          set = build_rights(rights, exact_rights)
          begin
            set.apply_to(fd)
          rescue ex
            dir.close
            raise ex
          end
        end
        dir
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # :nodoc:
    # Build the `Rights` to apply to a directory fd from the caller's list. Unless
    # `exact` is set, the rights `openat`/Crystal IO need are unioned in first.
    private def self.build_rights(rights : Enumerable(Symbol | Capability::Right),
                                  exact : Bool) : Capability::Rights
      set = exact ? Capability::Rights.new : Capability::Rights.new(:lookup, :fcntl, :fstat, :seek)
      rights.each { |right| set.set(Capability::Right.from(right)) }
      set
    end

    # Open `path` as a directory, yield the `Directory`, and close it afterwards.
    # Most callers keep the directory open across `cap_enter` and use the
    # non-block form instead.
    def self.open(path : String,
                  rights : Enumerable(Symbol | Capability::Right)? = nil,
                  exact_rights : Bool = false, &)
      dir = open(path, rights, exact_rights)
      begin
        yield dir
      ensure
        dir.close
      end
    end

    # `openat` `relpath` beneath this directory and return the raw fd. `relpath`
    # must be relative (no leading `/`); `..` escapes are rejected in-kernel by
    # `O_RESOLVE_BENEATH`. `mode` follows `File.open` (`"r"`, `"w"`, `"a"`,
    # `"r+"`, …). The caller owns the fd. Failures (including `ECAPMODE` for an
    # absolute path and `ENOTCAPABLE` for an escape or missing right) surface as
    # `File::Error`.
    #
    # `perm` is the create mode for `"w"`/`"a"` modes; like `open(2)` it is masked
    # by the process umask, so the default `0o644` yields `0o644 & ~umask` on disk
    # — matching `File.open`'s default create permissions.
    def open_fd(relpath : String, mode : String = "r", perm : Int32 = 0o644) : Int32
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        flags = Directory.open_flag(mode)
        fd = FreeBSD::Capsicum.syscall do
          LibOpenat.openat(@fd, relpath, flags, LibC::ModeT.new(perm))
        end
        if fd < 0
          raise ::File::Error.from_errno("openat", file: relpath)
        end
        fd
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # `openat` `relpath` and wrap the fd as an `IO::FileDescriptor`. Use when you
    # only need raw read/write on the fd.
    def open_io(relpath : String, mode : String = "r", perm : Int32 = 0o644) : IO::FileDescriptor
      IO::FileDescriptor.new(open_fd(relpath, mode, perm))
    end

    # `openat` `relpath` and wrap it as a real `::File` (same shape as
    # `File.open(path, mode)`, carrying `.path`). Block form closes the file.
    def open(relpath : String, mode : String = "r", perm : Int32 = 0o644) : ::File
      ::File.from_fd(::File.join(@base, relpath), open_fd(relpath, mode, perm), mode)
    end

    # :ditto:
    def open(relpath : String, mode : String = "r", perm : Int32 = 0o644, &)
      file = open(relpath, mode, perm)
      begin
        yield file
      ensure
        file.close
      end
    end

    # `fstatat` `relpath` beneath this directory and return its `File::Info`, or
    # `nil` if it does not exist. `relpath` must be relative; `..` escapes are
    # rejected in-kernel by `AT_RESOLVE_BENEATH`. With `follow_symlinks: false`
    # the link itself is stat'd (`lstat` semantics). Needs `:lookup` + `:fstat`
    # on the directory fd (the default rights provide both); other errnos raise
    # `File::Error`.
    def info?(relpath : String, follow_symlinks : Bool = true) : ::File::Info?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        flag = LibOpenat::AT_RESOLVE_BENEATH
        flag |= LibOpenat::AT_SYMLINK_NOFOLLOW unless follow_symlinks
        stat = uninitialized LibC::Stat
        ret = FreeBSD::Capsicum.syscall do
          LibOpenat.fstatat(@fd, relpath, pointerof(stat), flag)
        end
        if ret == 0
          ::File::Info.new(stat)
        elsif ::File::NotFoundError.os_error?(Errno.value)
          nil
        else
          raise ::File::Error.from_errno("fstatat", file: relpath)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # True if `relpath` exists beneath this directory (`faccessat` with `F_OK`).
    # A `..`/absolute escape is reported as non-existent, not raised.
    def exists?(relpath : String) : Bool
      accessible?(relpath, LibC::F_OK)
    end

    # True if `faccessat(relpath, flag)` succeeds beneath this directory. `flag`
    # is an `access(2)` mode (`F_OK`/`R_OK`/`W_OK`/`X_OK`). Non-raising, mirroring
    # the stdlib `File.readable?`/`writable?` family.
    def accessible?(relpath : String, flag : Int32) : Bool
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        FreeBSD::Capsicum.syscall do
          LibOpenat.faccessat(@fd, relpath, flag, LibOpenat::AT_RESOLVE_BENEATH)
        end == 0
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # The names directly under `relpath` (default: this directory), **including**
    # `"."` and `".."` — parity with `Dir.entries`. Needs `:read` + `:lookup` +
    # `:fstat` on the directory fd (the default rights provide all three).
    def entries(relpath : String = ".") : Array(String)
      list(relpath, all: true)
    end

    # The names directly under `relpath`, **excluding** `"."` and `".."` — parity
    # with `Dir.children`.
    def children(relpath : String = ".") : Array(String)
      list(relpath, all: false)
    end

    # Yield each child name under `relpath`, excluding `"."` and `".."`.
    def each_child(relpath : String = ".", &) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        dirp = opendir_at(relpath)
        label = ::File.join(@base, relpath)
        begin
          while entry = Crystal::System::Dir.next_entry(dirp, label)
            name = entry.name
            yield name unless name == "." || name == ".."
          end
        ensure
          Crystal::System::Dir.close(dirp, label)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # :nodoc:
    # Open a `DIR*` for `relpath` beneath this directory via `openat`+`fdopendir`.
    # Always opens a *fresh* subdirectory fd (even for `"."`), so `fdopendir`
    # owns it and `closedir` never touches this `Directory`'s own fd. Public so
    # the `integrate/dir` `Crystal::System::Dir.open` hook can reuse it.
    def opendir_at(relpath : String) : LibC::DIR*
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        subfd = FreeBSD::Capsicum.syscall do
          LibOpenat.openat(@fd, relpath,
            LibOpenat::O_RDONLY | LibOpenat::O_DIRECTORY |
            LibOpenat::O_RESOLVE_BENEATH | LibC::O_CLOEXEC)
        end
        if subfd < 0
          raise ::File::Error.from_errno("openat", file: relpath)
        end
        dirp = LibOpenat.fdopendir(subfd)
        if dirp.null?
          err = Errno.value
          LibC.close(subfd)
          Errno.value = err
          raise ::File::Error.from_errno("fdopendir", file: relpath)
        end
        dirp
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    private def list(relpath : String, all : Bool) : Array(String)
      names = [] of String
      each_with_dotdot(relpath) do |name|
        next if !all && (name == "." || name == "..")
        names << name
      end
      names
    end

    private def each_with_dotdot(relpath : String, &) : Nil
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        dirp = opendir_at(relpath)
        label = ::File.join(@base, relpath)
        begin
          while entry = Crystal::System::Dir.next_entry(dirp, label)
            yield entry.name
          end
        ensure
          Crystal::System::Dir.close(dirp, label)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # The directory fd's current effective Capsicum rights (`cap_rights_get`).
    def rights : Capability::Rights
      Capability::Rights.of(@fd)
    end

    def close : Nil
      return if @closed
      LibC.close(@fd)
      @closed = true
    end

    def closed? : Bool
      @closed
    end

    def finalize
      close
    end

    # The directory fd, for interop where a raw fd is expected.
    def to_unsafe : Int32
      @fd
    end

    # :nodoc:
    # Map a `File.open` mode string to `open(2)` flags, then OR-in the safety
    # flags every sandbox openat should carry (`O_CLOEXEC`, `O_RESOLVE_BENEATH`).
    # Reimplements the parsing of Crystal's `Crystal::System::File.open_flag`,
    # which is `private` and unreachable.
    def self.open_flag(mode : String) : Int32
      raise "No file open mode specified" if mode.empty?

      m = 0
      o = 0
      case mode[0]
      when 'r'
        m = LibC::O_RDONLY
      when 'w'
        m = LibC::O_WRONLY
        o = LibC::O_CREAT | LibC::O_TRUNC
      when 'a'
        m = LibC::O_WRONLY
        o = LibC::O_CREAT | LibC::O_APPEND
      else
        raise "Invalid file open mode: '#{mode}'"
      end

      case mode.size
      when 1
        # nothing
      when 2
        case mode[1]
        when '+'
          m = LibC::O_RDWR
        when 'b'
          # nothing — POSIX compatibility flag, no effect
        else
          raise "Invalid file open mode: '#{mode}'"
        end
      when 3
        unless mode.ends_with?("+b") || mode.ends_with?("b+")
          raise "Invalid file open mode: '#{mode}'"
        end
        m = LibC::O_RDWR
      else
        raise "Invalid file open mode: '#{mode}'"
      end

      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        m | o | LibC::O_CLOEXEC | LibOpenat::O_RESOLVE_BENEATH
      {% else %}
        m | o
      {% end %}
    end

    private def check_open!
      raise Error.new("directory is closed") if @closed
    end
  end

  # Directories registered for transparent `File.open` routing, keyed by their
  # normalized base path. See `register_directory` and `directory_for`.
  @@directories = {} of String => Directory

  # The registered directories, keyed by base path.
  def self.directories : Hash(String, Directory)
    @@directories
  end

  # Register `dir` so that `File.open` of any path beneath `dir.base` is routed
  # through its `openat` (when `freebsd/capsicum/integrate/file` is required).
  # Keyed by `dir.base`; registering a second directory at the same base
  # replaces the first. Returns `dir`.
  def self.register_directory(dir : Directory) : Directory
    @@directories[dir.base] = dir
  end

  # Remove `dir` from the registry.
  def self.unregister_directory(dir : Directory) : Nil
    @@directories.delete(dir.base)
  end

  # Empty the directory registry.
  def self.clear_directories : Nil
    @@directories.clear
  end

  # Find the registered directory that `path` lives beneath and the path
  # relative to it, or `nil` if none matches. When several bases match, the
  # longest (most specific) one wins, so `/var/data` is preferred over `/var`. A
  # path that would escape a base (`/variant` vs base `/var`) does not match it.
  #
  # Only absolute paths are routed: they are normalized *lexically* (collapsing
  # `.`/`..` without consulting the cwd, which `getcwd(2)` makes unavailable in
  # capability mode). A relative path returns `nil` and falls through to libc.
  def self.directory_for(path : String) : {Directory, String}?
    return nil if @@directories.empty?

    p = ::Path[path]
    return nil unless p.absolute?
    normalized = p.normalize
    best : {Directory, String}? = nil
    best_len = -1

    @@directories.each do |base, dir|
      rel = normalized.relative_to?(::Path[base])
      next unless rel
      # `relative_to?` emits `..` for siblings/escapes; only accept genuine
      # descendants. The empty relative path (the base itself) is not a file.
      next if rel.parts.includes?("..")
      rel_str = rel.to_s
      next if rel_str.empty? || rel_str == "."

      if base.size > best_len
        best = {dir, rel_str}
        best_len = base.size
      end
    end

    best
  end

  # Like `directory_for`, but also matches `path` when it *is* a registered base
  # exactly, returning `{dir, "."}`. Used by the `Dir.open` routing so listing the
  # docroot root itself works (`directory_for` rejects the base because it maps to
  # an empty relative path — meaningless for `File.open` but valid for listing).
  def self.directory_or_base_for(path : String) : {Directory, String}?
    return nil if @@directories.empty?
    p = ::Path[path]
    return nil unless p.absolute?
    if dir = @@directories[p.normalize.to_s]?
      return {dir, "."}
    end
    directory_for(path)
  end
end
