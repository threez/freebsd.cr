require "../casper"
require "../capsicum/file_from_fd"
require "./integrate/file"

{% if flag?(:freebsd) || flag?(:dragonfly) %}
  @[Link("cap_fileargs")]
  lib LibCapFileArgs
    type FileArgs = Void*

    FA_OPEN     = 0x00000001
    FA_LSTAT    = 0x00000002
    FA_REALPATH = 0x00000004

    # struct cap_rights is opaque to us here; pass nil for "all rights".
    fun fileargs_init(argc : Int32,
                      argv : LibC::Char**,
                      flags : Int32,
                      mode : LibC::ModeT,
                      rightsp : Void*,
                      fa_flags : Int32) : FileArgs

    fun fileargs_cinit(chan : LibCasper::CapChannel,
                       argc : Int32,
                       argv : LibC::Char**,
                       flags : Int32,
                       mode : LibC::ModeT,
                       rightsp : Void*,
                       fa_flags : Int32) : FileArgs

    fun fileargs_open(fa : FileArgs, name : LibC::Char*) : Int32
    fun fileargs_lstat(fa : FileArgs, name : LibC::Char*, sb : LibC::Stat*) : Int32
    fun fileargs_realpath(fa : FileArgs, name : LibC::Char*, resolved : LibC::Char*) : LibC::Char*
    fun fileargs_free(fa : FileArgs) : Void
  end
{% end %}

module FreeBSD::Casper
  # Casper's `system.fileargs` service: open a pre-declared set of paths from
  # a sandboxed process by delegating to the helper. The set of allowed paths
  # is fixed when the service is created — opens of any other path are
  # rejected.
  #
  # Unlike the other services this does not subclass `Service`, because the
  # libcap_fileargs handle is its own opaque type (`fileargs_t*`), not a
  # generic `cap_channel_t*`.
  class Service::FileArgs
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      # Flag enabling `open(2)` via the helper (default). Pass to `fa_flags`.
      OPEN = LibCapFileArgs::FA_OPEN
      # Flag enabling `lstat(2)` via the helper. Pass to `fa_flags`.
      LSTAT = LibCapFileArgs::FA_LSTAT
      # Flag enabling `realpath(3)` via the helper. Pass to `fa_flags`.
      REALPATH = LibCapFileArgs::FA_REALPATH
    {% else %}
      # Flag enabling `open(2)` via the helper (default). Pass to `fa_flags`.
      OPEN = 0x1
      # Flag enabling `lstat(2)` via the helper. Pass to `fa_flags`.
      LSTAT = 0x2
      # Flag enabling `realpath(3)` via the helper. Pass to `fa_flags`.
      REALPATH = 0x4
    {% end %}

    # Set of paths declared at construction time. Only these paths may be opened.
    getter declared : Set(String)
    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      @handle : LibCapFileArgs::FileArgs

      protected def initialize(@handle : LibCapFileArgs::FileArgs, @declared : Set(String))
      end
    {% else %}
      @handle : Void*

      protected def initialize(@handle : Void*, @declared : Set(String))
      end
    {% end %}
    @closed = false

    # Create a fileargs handle that may open the listed `paths`. Opens its own
    # connection to the Casper daemon — equivalent to `fileargs_init(3)`.
    def self.create(paths : Enumerable(String),
                    flags : Int32 = 0,
                    mode : UInt16 = 0o644_u16,
                    fa_flags : Int32 = OPEN) : FileArgs
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        fa = build_argv(paths) do |argv, count|
          LibCapFileArgs.fileargs_init(count, argv, flags, mode,
            Pointer(Void).null, fa_flags)
        end
        new(fa, paths.to_set)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Same as `.create`, but uses an existing Casper `Channel`.
    def self.create(channel : Channel,
                    paths : Enumerable(String),
                    flags : Int32 = 0,
                    mode : UInt16 = 0o644_u16,
                    fa_flags : Int32 = OPEN) : FileArgs
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        fa = build_argv(paths) do |argv, count|
          LibCapFileArgs.fileargs_cinit(channel.to_unsafe, count, argv,
            flags, mode, Pointer(Void).null, fa_flags)
        end
        new(fa, paths.to_set)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # True iff `path` was declared at creation time and may be opened.
    def declared?(path : String) : Bool
      @declared.includes?(path)
    end

    # Open a declared path and return the raw file descriptor. The caller owns
    # the fd and is responsible for closing it.
    def open_fd(path : String) : Int32
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        fd = LibCapFileArgs.fileargs_open(@handle, path)
        if fd < 0
          raise ::File::Error.from_errno("fileargs_open", file: path)
        end
        fd
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # Open a declared path and wrap it as an `IO::FileDescriptor`. Use this
    # when you only need raw read/write on the fd.
    def open_io(path : String) : IO::FileDescriptor
      IO::FileDescriptor.new(open_fd(path))
    end

    # Open a declared path and wrap it as a `::File` — same shape as
    # `File.open(path, mode)` but bypassing the global filesystem (the fd
    # comes from the helper). The resulting `File` carries `.path` and is
    # usable wherever a Crystal `::File` is expected.
    #
    # Note: `mode` here is informational. The actual `open(2)` flags were
    # fixed when this `FileArgs` was created; reading vs writing capability
    # follows that, not `mode`.
    def open_file(path : String, mode : String = "r") : ::File
      ::File.from_fd(path, open_fd(path), mode)
    end

    # Resolve a declared path's canonical form via `fileargs_realpath(3)`.
    # Requires `REALPATH` in `fa_flags` at creation.
    def realpath(path : String) : String
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        buf = Bytes.new(LibC::PATH_MAX)
        ptr = LibCapFileArgs.fileargs_realpath(@handle, path, buf.to_unsafe.as(LibC::Char*))
        if ptr.null?
          raise ::File::Error.from_errno("fileargs_realpath", file: path)
        end
        String.new(ptr)
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    # lstat a declared path. Requires `LSTAT` in `fa_flags` at creation.
    def lstat(path : String) : ::File::Info?
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        check_open!
        stat = uninitialized LibC::Stat
        if LibCapFileArgs.fileargs_lstat(@handle, path, pointerof(stat)) == 0
          ::File::Info.new(stat)
        else
          nil
        end
      {% else %}
        raise ::FreeBSD::Capsicum::UnsupportedPlatformError.new
      {% end %}
    end

    def close : Nil
      return if @closed
      {% if flag?(:freebsd) || flag?(:dragonfly) %}
        LibCapFileArgs.fileargs_free(@handle)
      {% end %}
      @closed = true
    end

    def closed? : Bool
      @closed
    end

    def finalize
      close
    end

    {% if flag?(:freebsd) || flag?(:dragonfly) %}
      private def check_open!
        raise ::FreeBSD::Capsicum::Error.new("fileargs is closed") if @closed
      end

      # Build a NULL-terminated argv from `paths`, hand it to the block, raise
      # if the block returned a null handle.
      private def self.build_argv(paths : Enumerable(String), & : LibC::Char**, Int32 -> LibCapFileArgs::FileArgs) : LibCapFileArgs::FileArgs
        path_list = paths.to_a
        # Anchor each path String so its byte buffer isn't collected mid-call.
        argv = Array(LibC::Char*).new(path_list.size + 1)
        path_list.each { |p| argv << p.to_unsafe }
        argv << Pointer(LibC::Char).null
        handle = yield argv.to_unsafe, path_list.size
        if handle.null?
          raise ::FreeBSD::Capsicum::Error.from_errno("fileargs_init")
        end
        handle
      end
    {% end %}
  end

  @@fileargs : Service::FileArgs? = nil

  # The globally-installed Casper FileArgs service, if any. When set, the
  # `casper/integrate/file` integration routes `File.open` of declared paths
  # through this helper instead of `LibC.open`.
  def self.fileargs? : Service::FileArgs?
    @@fileargs
  end

  # Register `service` as the process-wide FileArgs handler.
  def self.install_fileargs(service : Service::FileArgs) : Service::FileArgs
    @@fileargs = service
  end

  # Convenience: create a FileArgs service for `paths` and install it. `flags`
  # follow `open(2)` (defaults to read-only); the helper opens each declared
  # path with these flags.
  def self.install_fileargs!(paths : Enumerable(String),
                             flags : Int32 = 0,
                             mode : UInt16 = 0o644_u16,
                             fa_flags : Int32 = Service::FileArgs::OPEN) : Service::FileArgs
    install_fileargs(Service::FileArgs.create(paths, flags: flags, mode: mode, fa_flags: fa_flags))
  end

  def self.uninstall_fileargs : Nil
    @@fileargs = nil
  end

  # Install the Casper `system.fileargs` service, injecting a `Crystal.main_user_code`
  # override. Arguments mirror `install_fileargs!`. Auto-requires `integrate/file`
  # so declared paths are transparently routed through the helper.
  #
  # ```
  # require "freebsd/casper/fileargs"
  #
  # FreeBSD::Casper.register_fileargs(
  #   ["/etc/hosts", "/etc/resolv.conf"],
  #   flags: LibC::O_RDONLY,
  #   fa_flags: FreeBSD::Casper::Service::FileArgs::OPEN | FreeBSD::Casper::Service::FileArgs::LSTAT,
  # )
  #
  # FreeBSD::Capsicum.sandbox!
  # File.read("/etc/hosts") # works — routed through fileargs
  # ```
  macro register_fileargs(paths, flags = 0, mode = 0o644_u16, fa_flags = FreeBSD::Casper::Service::FileArgs::OPEN)
    \{% if flag?(:freebsd) || flag?(:dragonfly) %}
      # Plain top-level install (runtime up); no main_user_code override. See net.cr.
      FreeBSD::Casper.install_fileargs!({{paths}}, flags: {{flags}}, mode: {{mode}}, fa_flags: {{fa_flags}})
    \{% end %}
  end
end
