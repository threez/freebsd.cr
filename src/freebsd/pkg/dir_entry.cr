module FreeBSD::Pkg
  # An opaque handle to a directory entry within a package.
  #
  # Like `FileEntry`, `struct pkg_dir` has no public C accessor functions in
  # libpkg's exported API. This struct is useful only as an identity token.
  # Use `Package#has_dir?` for path-based existence checks.
  struct DirEntry
    def initialize(@handle : LibPkg::PkgDir)
    end

    # Returns `true` if this handle is null (should not occur in normal use).
    def null? : Bool
      @handle.null?
    end

    # Returns the underlying `pkg_dir*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgDir
      @handle
    end
  end
end
