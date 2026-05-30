module FreeBSD::Pkg
  # Internal iterator wrapper around a `pkgdb_it*`.
  #
  # Not part of the public API. Used by `Database` to stream or collect
  # `Package` objects. Always freed when closed or finalized.
  private class Iterator
    include PkgHelpers

    def initialize(@handle : LibPkg::PkgDbIt, @flags : LoadFlags)
    end

    # Yields each package in the iterator result set.
    #
    # libpkg reuses the same `struct pkg` allocation across `pkgdb_it_next`
    # calls. The `Package` passed to the block is **ephemeral** — its handle
    # is invalidated on the next iteration. Do not retain it outside the block.
    # Use `collect` to get independently-owned packages.
    def each(& : Package ->) : Nil
      {% if flag?(:freebsd) %}
        return if @handle.null?
        pkg_ptr = Pointer(Void).null.as(LibPkg::PkgHandle)
        loop do
          rc = LibPkg.pkgdb_it_next(@handle, pointerof(pkg_ptr), @flags.value)
          break if rc == LibPkg::PkgErrorT::End.value
          check_rc!(rc, "pkgdb_it_next")
          yield Package.new(pkg_ptr, owns: false)
        end
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    # Returns all packages as an `Array(Package)`.
    # Each package in the array has its own libpkg-allocated handle and
    # will be freed when garbage-collected.
    def collect : Array(Package)
      {% if flag?(:freebsd) %}
        result = [] of Package
        return result if @handle.null?
        pkg_ptr = Pointer(Void).null.as(LibPkg::PkgHandle)
        loop do
          rc = LibPkg.pkgdb_it_next(@handle, pointerof(pkg_ptr), @flags.value)
          break if rc == LibPkg::PkgErrorT::End.value
          check_rc!(rc, "pkgdb_it_next")
          # libpkg allocates a new struct pkg when pkg_ptr starts as null, and
          # returns the same pointer on subsequent calls (reusing the allocation).
          # To obtain independently-owned packages in an array, we reset pkg_ptr
          # to null after each successful call so that libpkg allocates fresh
          # memory for the next entry.
          result << Package.new(pkg_ptr, owns: true)
          pkg_ptr = Pointer(Void).null.as(LibPkg::PkgHandle)
        end
        result
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    def count : Int32
      {% if flag?(:freebsd) %}
        @handle.null? ? 0 : LibPkg.pkgdb_it_count(@handle)
      {% else %}
        raise UnsupportedPlatformError.new
      {% end %}
    end

    def close : Nil
      {% if flag?(:freebsd) %}
        unless @handle.null?
          LibPkg.pkgdb_it_free(@handle)
          @handle = Pointer(Void).null.as(LibPkg::PkgDbIt)
        end
      {% end %}
    end

    def finalize
      close
    end
  end
end
