module FreeBSD::Pkg
  # Bitmask controlling which package relations are loaded from the database.
  #
  # Pass as the `flags:` argument to `Database#query`, `Database#each`, and
  # related query methods. Combine values with `|`, or use a symbol / array:
  #
  # ```
  # db.query("pkg", flags: :deps)
  # db.query("pkg", flags: [:deps, :annotations])
  # db.query("pkg", flags: LoadFlags::Deps | LoadFlags::Annotations)
  # ```
  #
  # `None` (0) corresponds to `PKG_LOAD_BASIC` — only scalar metadata fields
  # such as name, version, and origin are guaranteed to be populated.
  @[Flags]
  enum LoadFlags : UInt32
    # Load direct dependencies (`pkg_deps`).
    Deps = 1
    # Load reverse dependencies — packages that depend on this one (`pkg_rdeps`).
    Rdeps = 2
    # Load the list of installed files (`pkg_files`).
    Files = 4
    # Load pre/post-install scripts.
    Scripts = 8
    # Load build-time and run-time options.
    Options = 16
    # Load the list of installed directories (`pkg_dirs`).
    Dirs = 32
    # Load the package categories list.
    Categories = 64
    # Load the package licenses list.
    Licenses = 128
    # Load the list of system users created by the package.
    Users = 256
    # Load the list of system groups created by the package.
    Groups = 512
    # Load shared libraries required by the package (`pkg_shlibs_required`).
    ShlibsRequired = 1024
    # Load shared libraries provided by the package (`pkg_shlibs_provided`).
    ShlibsProvided = 2048
    # Load package annotations (key/value pairs).
    Annotations = 4096
    # Load conflict declarations.
    Conflicts = 8192
    # Load abstract `provides` strings.
    Provides = 16384
    # Load abstract `requires` strings.
    Requires = 32768
  end
end
