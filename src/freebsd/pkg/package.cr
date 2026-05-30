module FreeBSD::Pkg
  # A package — installed, available from a repository, or loaded from a file.
  #
  # Attribute access uses `pkg_get_element`, which returns a heap-allocated
  # `struct pkg_el` that is freed immediately after reading. Only attributes
  # that were loaded (controlled by `LoadFlags`) are populated; others return
  # `nil` or an empty collection.
  #
  # ## Ownership
  #
  # When `owns: true` (the default for packages returned by `Database#query`),
  # the underlying `struct pkg` is freed in `finalize`. When `owns: false`
  # (packages yielded inside `Database#each` blocks), libpkg manages the
  # memory — do **not** retain such a `Package` beyond the block.
  class Package
    # Represents a package type as returned by `pkg_type(3)`.
    enum Type : UInt32
      # No type set.
      None = 0
      # Package loaded from a local `.pkg` file.
      File = 1
      # Package loaded from a stream.
      Stream = 2
      # Package available from a remote repository.
      Remote = 4
      # Package installed in the local database.
      Installed = 8
      # Old-format local package file.
      OldFile = 16
      # Group of remote packages.
      GroupRemote = 32
      # Group of installed packages.
      GroupInstalled = 64
    end

    def initialize(@handle : LibPkg::PkgHandle, @owns : Bool = true)
    end

    # -------------------------------------------------------------------
    # String attributes
    # -------------------------------------------------------------------

    # Package name (e.g. `"nginx"`).
    def name : String
      get_string(LibPkg::PkgAttr::Name) || ""
    end

    # Package version string (e.g. `"1.26.1,3"`).
    def version : String
      get_string(LibPkg::PkgAttr::Version) || ""
    end

    # Port origin (e.g. `"www/nginx"`).
    def origin : String
      get_string(LibPkg::PkgAttr::Origin) || ""
    end

    # One-line package comment.
    def comment : String
      get_string(LibPkg::PkgAttr::Comment) || ""
    end

    # Full package description.
    def description : String
      get_string(LibPkg::PkgAttr::Desc) || ""
    end

    # CPU architecture string (e.g. `"amd64"`).
    def arch : String
      get_string(LibPkg::PkgAttr::Arch) || ""
    end

    # ABI string as used by pkg (e.g. `"FreeBSD:14:amd64"`).
    def abi : String
      get_string(LibPkg::PkgAttr::Abi) || ""
    end

    # Port maintainer email address.
    def maintainer : String
      get_string(LibPkg::PkgAttr::Maintainer) || ""
    end

    # Project homepage URL.
    def www : String
      get_string(LibPkg::PkgAttr::Www) || ""
    end

    # Installation prefix (e.g. `"/usr/local"`).
    def prefix : String
      get_string(LibPkg::PkgAttr::Prefix) || ""
    end

    # SHA256 checksum of the package archive, or `nil` if not available.
    def cksum : String?
      get_string(LibPkg::PkgAttr::Cksum)
    end

    # Unique identifier combining name and origin (e.g. `"nginx,www/nginx"`).
    def uniqueid : String
      get_string(LibPkg::PkgAttr::Uniqueid) || ""
    end

    # Name of the repository this package came from, or `nil` for local packages.
    def repo_name : String?
      get_string(LibPkg::PkgAttr::Reponame)
    end

    # URL of the repository this package came from, or `nil` for local packages.
    def repo_url : String?
      get_string(LibPkg::PkgAttr::Repourl)
    end

    # Manifest digest used for repository consistency checks, or `nil` if not set.
    def digest : String?
      get_string(LibPkg::PkgAttr::Digest)
    end

    # Dependency formula string expressing version constraints, or `nil` if not set.
    def dep_formula : String?
      get_string(LibPkg::PkgAttr::DepFormula)
    end

    # -------------------------------------------------------------------
    # Integer attributes
    # -------------------------------------------------------------------

    # Installed size on disk in bytes.
    def installed_size : Int64
      get_int64(LibPkg::PkgAttr::Flatsize) || 0_i64
    end

    # Compressed archive size in bytes (the download size).
    def archive_size : Int64
      get_int64(LibPkg::PkgAttr::Pkgsize) || 0_i64
    end

    # Internal SQLite row ID for this package record.
    def row_id : Int64
      get_int64(LibPkg::PkgAttr::Rowid) || 0_i64
    end

    # Time the package was installed.
    # Returns `Time::UNIX_EPOCH` when not loaded or not set.
    def installed_at : Time
      ts = get_int64(LibPkg::PkgAttr::Time) || 0_i64
      Time.unix(ts)
    end

    # -------------------------------------------------------------------
    # Boolean attributes
    # -------------------------------------------------------------------

    # True if this package was installed automatically as a dependency.
    def automatic? : Bool
      get_bool(LibPkg::PkgAttr::Automatic) || false
    end

    # True if the package is locked (protected from removal/upgrade).
    def locked? : Bool
      get_bool(LibPkg::PkgAttr::Locked) || false
    end

    # True if the package is marked vital (removal requires --force).
    def vital? : Bool
      get_bool(LibPkg::PkgAttr::Vital) || false
    end

    # -------------------------------------------------------------------
    # Package type / validity
    # -------------------------------------------------------------------

    # Returns the package type (installed, remote, file, etc.).
    def type : Type
      {% if flag?(:freebsd) %}
        Type.new(LibPkg.pkg_type(@handle).value)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns `true` if the underlying `struct pkg` has been fully initialised
    # by libpkg and is safe to read from.
    def valid? : Bool
      {% if flag?(:freebsd) %}
        LibPkg.pkg_is_valid(@handle) == 1
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # StringList attributes (require matching LoadFlags)
    # -------------------------------------------------------------------

    # Returns the package categories (e.g. `["www", "net"]`).
    # Requires `LoadFlags::Categories`.
    def categories : Array(String)
      get_stringlist(LibPkg::PkgAttr::Categories)
    end

    # Returns the package licenses (e.g. `["BSD2CLAUSE"]`).
    # Requires `LoadFlags::Licenses`.
    def licenses : Array(String)
      get_stringlist(LibPkg::PkgAttr::Licenses)
    end

    # Returns shared libraries required by this package (e.g. `["libssl.so.30"]`).
    # Requires `LoadFlags::ShlibsRequired`.
    def shlibs_required : Array(String)
      get_stringlist(LibPkg::PkgAttr::ShlibsRequired)
    end

    # Returns shared libraries provided by this package (e.g. `["libpkg.so.4"]`).
    # Requires `LoadFlags::ShlibsProvided`.
    def shlibs_provided : Array(String)
      get_stringlist(LibPkg::PkgAttr::ShlibsProvided)
    end

    # Returns abstract capability strings this package provides.
    # Requires `LoadFlags::Provides`.
    def provides : Array(String)
      get_stringlist(LibPkg::PkgAttr::Provides)
    end

    # Returns abstract capability strings this package requires.
    # Requires `LoadFlags::Requires`.
    def requires : Array(String)
      get_stringlist(LibPkg::PkgAttr::Requires)
    end

    # -------------------------------------------------------------------
    # KVList attribute (annotations)
    # -------------------------------------------------------------------

    # Returns all annotations as a `Hash(String, String)`.
    # Requires `LoadFlags::Annotations`.
    def annotations : Hash(String, String)
      get_kvlist(LibPkg::PkgAttr::Annotations)
    end

    # -------------------------------------------------------------------
    # Dependency iteration (requires LoadFlags::Deps / LoadFlags::Rdeps)
    # -------------------------------------------------------------------

    # Yields each direct dependency.
    # The yielded `Dependency` is only valid inside the block.
    def each_dependency(& : Dependency ->) : Nil
      {% if flag?(:freebsd) %}
        dep = Pointer(Void).null.as(LibPkg::PkgDep)
        while LibPkg.pkg_deps(@handle, pointerof(dep)) == LibPkg::PkgErrorT::Ok.value
          yield Dependency.new(dep)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Yields each reverse dependency (packages that depend on this one).
    # The yielded `Dependency` is only valid inside the block.
    def each_reverse_dependency(& : Dependency ->) : Nil
      {% if flag?(:freebsd) %}
        dep = Pointer(Void).null.as(LibPkg::PkgDep)
        while LibPkg.pkg_rdeps(@handle, pointerof(dep)) == LibPkg::PkgErrorT::Ok.value
          yield Dependency.new(dep)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # File / directory iteration (requires LoadFlags::Files / LoadFlags::Dirs)
    # -------------------------------------------------------------------

    # Yields each file entry. The handle inside `FileEntry` is opaque —
    # paths cannot be retrieved via the public libpkg API.
    # Use `has_file?` for path-based existence checks instead.
    def each_file(& : FileEntry ->) : Nil
      {% if flag?(:freebsd) %}
        file = Pointer(Void).null.as(LibPkg::PkgFile)
        while LibPkg.pkg_files(@handle, pointerof(file)) == LibPkg::PkgErrorT::Ok.value
          yield FileEntry.new(file)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Yields each directory entry. See `each_file` for the opacity caveat.
    def each_dir(& : DirEntry ->) : Nil
      {% if flag?(:freebsd) %}
        dir = Pointer(Void).null.as(LibPkg::PkgDir)
        while LibPkg.pkg_dirs(@handle, pointerof(dir)) == LibPkg::PkgErrorT::Ok.value
          yield DirEntry.new(dir)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Existence checks
    # -------------------------------------------------------------------

    # Returns true if *path* is listed among this package's installed files.
    # Requires `LoadFlags::Files`.
    def has_file?(path : String) : Bool
      {% if flag?(:freebsd) %}
        LibPkg.pkg_has_file(@handle, path)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns true if *path* is listed among this package's installed directories.
    # Requires `LoadFlags::Dirs`.
    def has_dir?(path : String) : Bool
      {% if flag?(:freebsd) %}
        LibPkg.pkg_has_dir(@handle, path)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns the `FileEntry` for *path*, or `nil` if not found.
    # Requires `LoadFlags::Files`.
    def file_at(path : String) : FileEntry?
      {% if flag?(:freebsd) %}
        handle = LibPkg.pkg_get_file(@handle, path)
        handle.null? ? nil : FileEntry.new(handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns the `DirEntry` for *path*, or `nil` if not found.
    # Requires `LoadFlags::Dirs`.
    def dir_at(path : String) : DirEntry?
      {% if flag?(:freebsd) %}
        handle = LibPkg.pkg_get_dir(@handle, path)
        handle.null? ? nil : DirEntry.new(handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # -------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------

    # Returns the underlying `pkg*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgHandle
      @handle
    end

    def finalize
      {% if flag?(:freebsd) %}
        LibPkg.pkg_free(@handle) if @owns && !@handle.null?
      {% end %}
    end

    # -------------------------------------------------------------------
    # Private helpers — pkg_get_element dispatch
    # -------------------------------------------------------------------

    # Returns a String attribute, or nil if the attribute is absent/empty.
    private def get_string(attr : LibPkg::PkgAttr) : String?
      {% if flag?(:freebsd) %}
        el = LibPkg.pkg_get_element(@handle, attr)
        return nil if el.null?
        begin
          return nil unless el.value.type == LibPkg::PkgElT::Str
          # The payload union's first 8 bytes hold a const char* on amd64.
          ptr_addr = el.value.payload.to_unsafe.address
          cstr = Pointer(Pointer(LibC::Char)).new(ptr_addr).value
          cstr.null? ? nil : String.new(cstr)
        ensure
          LibC.free(el.as(Void*))
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    private def get_int64(attr : LibPkg::PkgAttr) : Int64?
      {% if flag?(:freebsd) %}
        el = LibPkg.pkg_get_element(@handle, attr)
        return nil if el.null?
        begin
          return nil unless el.value.type == LibPkg::PkgElT::Integer
          Pointer(Int64).new(el.value.payload.to_unsafe.address).value
        ensure
          LibC.free(el.as(Void*))
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    private def get_bool(attr : LibPkg::PkgAttr) : Bool?
      {% if flag?(:freebsd) %}
        el = LibPkg.pkg_get_element(@handle, attr)
        return nil if el.null?
        begin
          return nil unless el.value.type == LibPkg::PkgElT::Boolean
          el.value.payload[0] != 0
        ensure
          LibC.free(el.as(Void*))
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    private def get_stringlist(attr : LibPkg::PkgAttr) : Array(String)
      {% if flag?(:freebsd) %}
        result = [] of String
        el = LibPkg.pkg_get_element(@handle, attr)
        return result if el.null?
        begin
          return result unless el.value.type == LibPkg::PkgElT::StringList
          list_ptr = Pointer(LibPkg::PkgStringlist).new(el.value.payload.to_unsafe.address).value
          return result if list_ptr.null?
          it = LibPkg.pkg_stringlist_iterator(list_ptr)
          loop do
            cstr = LibPkg.pkg_stringlist_next(it)
            break if cstr.null?
            result << String.new(cstr)
          end
        ensure
          LibC.free(el.as(Void*))
        end
        result
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    private def get_kvlist(attr : LibPkg::PkgAttr) : Hash(String, String)
      {% if flag?(:freebsd) %}
        result = {} of String => String
        el = LibPkg.pkg_get_element(@handle, attr)
        return result if el.null?
        begin
          return result unless el.value.type == LibPkg::PkgElT::KvList
          list_ptr = Pointer(LibPkg::PkgKvlist).new(el.value.payload.to_unsafe.address).value
          return result if list_ptr.null?
          it = LibPkg.pkg_kvlist_iterator(list_ptr)
          loop do
            # pkg_kvlist_next returns a char*[2]: [key_ptr, value_ptr]
            pair = LibPkg.pkg_kvlist_next(it)
            break if pair.null?
            key_ptr = pair[0]
            val_ptr = pair[1]
            break if key_ptr.null?
            key = String.new(key_ptr)
            val = val_ptr.null? ? "" : String.new(val_ptr)
            result[key] = val
          end
        ensure
          LibC.free(el.as(Void*))
        end
        result
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end
  end
end
