module FreeBSD::Pkg
  # An opaque handle to a file entry within a package.
  #
  # `struct pkg_file` has no public C accessor functions in libpkg's exported
  # API — the path and other metadata fields are private implementation
  # details. This struct is therefore useful only as an identity token:
  # you can obtain one via `Package#each_file` (to count files or confirm
  # iteration) or `Package#file_at` (to check whether a specific path is
  # part of the package), but you cannot read back the path from the handle.
  #
  # For path-based existence checks, use `Package#has_file?` instead.
  struct FileEntry
    def initialize(@handle : LibPkg::PkgFile)
    end

    # Returns `true` if this handle is null (should not occur in normal use).
    def null? : Bool
      @handle.null?
    end

    # Returns the underlying `pkg_file*` pointer for use with raw `LibPkg` calls.
    def to_unsafe : LibPkg::PkgFile
      @handle
    end
  end
end
