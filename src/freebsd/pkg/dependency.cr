module FreeBSD::Pkg
  # A single package dependency entry.
  #
  # Instances are only valid during the `Package#each_dependency` /
  # `Package#each_reverse_dependency` block — libpkg manages the underlying memory
  # as part of the package's linked list and may reuse it on the next call.
  # Do not store a `Dependency` beyond the block in which it was yielded.
  struct Dependency
    def initialize(@handle : LibPkg::PkgDep)
    end

    # Package name of the dependency (e.g. `"openssl"`).
    def name : String
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_dep_get(@handle, LibPkg::PkgDepAttr::Name)
        cstr.null? ? "" : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Port origin of the dependency (e.g. `"security/openssl"`).
    def origin : String
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_dep_get(@handle, LibPkg::PkgDepAttr::Origin)
        cstr.null? ? "" : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Version string of the dependency as recorded in the local database.
    def version : String
      {% if flag?(:freebsd) %}
        cstr = LibPkg.pkg_dep_get(@handle, LibPkg::PkgDepAttr::Version)
        cstr.null? ? "" : String.new(cstr)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns `true` if the dependency package is locked (protected from removal/upgrade).
    def locked? : Bool
      {% if flag?(:freebsd) %}
        LibPkg.pkg_dep_is_locked(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns the underlying `pkg_dep*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgDep
      @handle
    end
  end
end
