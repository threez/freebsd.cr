module FreeBSD::Pkg
  # Wraps a `struct pkg_event*` for the duration of an event callback.
  #
  # Do NOT retain an `Event` beyond the callback block — the pointer is only
  # valid for the callback's stack frame.
  #
  # ## Payload accessors
  #
  # Accessor methods read the C union payload at byte offset 8 from the struct
  # start (4-byte `type` field + 4 bytes alignment padding on amd64). They
  # return `nil` when the event kind does not carry that payload.
  struct Event
    # All event kinds — a direct alias of `LibPkg::PkgEventT` (the C enum).
    # Values are authoritative in `lib_pkg.cr`; see there for the full list.
    # All event kinds emitted by libpkg. Direct alias of `LibPkg::PkgEventT`.
    # See `lib_pkg.cr` for the authoritative value list.
    alias Kind = LibPkg::PkgEventT

    def initialize(@raw : LibPkg::PkgEvent*)
    end

    # The event kind discriminant.
    def kind : Kind
      {% if flag?(:freebsd) %}
        @raw.value.type
      {% else %}
        Kind::InstallBegin
      {% end %}
    end

    # Human-readable message. Valid for: `Notice`, `Error`, `ProgressStart`,
    # `Message`, `Debug`.
    def message : String?
      cstr = read_string_at(0)
      cstr.null? ? nil : String.new(cstr)
    end

    # URL being fetched. Valid for: `Fetching`, `FetchBegin`, `FetchFinished`.
    def url : String?
      cstr = read_string_at(0)
      cstr.null? ? nil : String.new(cstr)
    end

    # The package involved. Valid for `InstallBegin`/`InstallFinished`,
    # `DeinstallBegin`/`DeinstallFinished`, `ExtractBegin`/`ExtractFinished`,
    # `AlreadyInstalled`, `Locked`, `Required`, `MissingDep`, etc.
    def package : Package?
      {% if flag?(:freebsd) %}
        ptr = Pointer(LibPkg::PkgHandle).new(payload_ptr.address).value
        ptr.null? ? nil : Package.new(ptr, owns: false)
      {% else %}
        nil
      {% end %}
    end

    # The outgoing (old) package for upgrade events.
    # Valid for: `UpgradeBegin`, `UpgradeFinished`.
    def old_package : Package?
      {% if flag?(:freebsd) %}
        ptr = Pointer(LibPkg::PkgHandle).new(payload_ptr.address).value
        ptr.null? ? nil : Package.new(ptr, owns: false)
      {% else %}
        nil
      {% end %}
    end

    # The incoming (new) package for upgrade events.
    # Valid for: `UpgradeBegin`, `UpgradeFinished`.
    def new_package : Package?
      {% if flag?(:freebsd) %}
        # new pkg pointer follows old pkg pointer (second pointer-width slot)
        ptr = Pointer(LibPkg::PkgHandle).new((payload_ptr + sizeof(Pointer(Void))).address).value
        ptr.null? ? nil : Package.new(ptr, owns: false)
      {% else %}
        nil
      {% end %}
    end

    # Bytes downloaded so far. Valid for: `ProgressTick`.
    def progress_current : Int64?
      Pointer(Int64).new(payload_ptr.address).value
    end

    # Total bytes to download. Valid for: `ProgressTick`.
    def progress_total : Int64?
      Pointer(Int64).new((payload_ptr + 8).address).value
    end

    # Number of packages processed so far. Valid for: `UpdateAdd`, `UpdateRemove`.
    def update_done : Int32?
      Pointer(Int32).new(payload_ptr.address).value
    end

    # Total number of packages to process. Valid for: `UpdateAdd`, `UpdateRemove`.
    def update_total : Int32?
      Pointer(Int32).new((payload_ptr + 4).address).value
    end

    # Debug verbosity level. Valid for: `Debug`.
    def debug_level : Int32?
      Pointer(Int32).new(payload_ptr.address).value
    end

    # Repository name. Valid for: `NoRemoteDb`.
    def repo_name : String?
      cstr = read_string_at(0)
      cstr.null? ? nil : String.new(cstr)
    end

    # System error number. Valid for: `Errno`.
    def error_no : Int32?
      Pointer(Int32).new(payload_ptr.address).value
    end

    # Function that set errno. Valid for: `Errno`.
    def error_func : String?
      cstr = read_string_at(sizeof(Int32))
      cstr.null? ? nil : String.new(cstr)
    end

    # Argument to the failing function. Valid for: `Errno`.
    def error_arg : String?
      cstr = read_string_at(sizeof(Int32) + sizeof(Pointer(Void)))
      cstr.null? ? nil : String.new(cstr)
    end

    # Name of the package that was not found. Valid for: `NotFound`.
    def pkg_name : String?
      cstr = read_string_at(0)
      cstr.null? ? nil : String.new(cstr)
    end

    # Trigger script name. Valid for: `Trigger`.
    def trigger_name : String?
      cstr = read_string_at(0)
      cstr.null? ? nil : String.new(cstr)
    end

    # Number of conflicting packages. Valid for: `IntegritycheckFinished`.
    def conflicting : Int32?
      Pointer(Int32).new(payload_ptr.address).value
    end

    # -------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------

    # Returns a pointer to the union payload (byte offset 8 from struct start).
    # The C layout on amd64: 4-byte type + 4-byte padding → union at offset 8.
    private def payload_ptr : UInt8*
      @raw.as(UInt8*) + 8
    end

    private def read_string_at(offset : Int) : LibC::Char*
      addr = (payload_ptr + offset).address
      Pointer(Pointer(LibC::Char)).new(addr).value
    end
  end

  # Global event callback registration for libpkg progress and status events.
  #
  # Only one callback can be registered at a time — libpkg overwrites on
  # each `pkg_event_register` call.
  #
  # ```
  # FreeBSD::Pkg::EventCallbacks.register do |ev|
  #   case ev.kind
  #   when .install_begin? then puts "Installing #{ev.package.try(&.name)}"
  #   when .progress_tick? then print "."
  #   when .error?         then STDERR.puts ev.message
  #   end
  # end
  # ```
  module EventCallbacks
    # GC-stable class-level storage for the C callback closure.
    @@callback : Proc(FreeBSD::Pkg::Event, Nil)? = nil

    {% if flag?(:freebsd) %}
      @@c_callback = LibPkg::PkgEventCb.new do |_data, ev_ptr|
        @@callback.try(&.call(FreeBSD::Pkg::Event.new(ev_ptr)))
        0_i32
      end
    {% end %}

    # Register *block* as the global event callback. The callback fires
    # synchronously during `Jobs#apply` and other mutating operations.
    #
    # The callback remains active until the next `register` call.
    def self.register(&block : FreeBSD::Pkg::Event ->) : Nil
      @@callback = block
      {% if flag?(:freebsd) %}
        LibPkg.pkg_event_register(@@c_callback, Pointer(Void).null)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end
  end
end
