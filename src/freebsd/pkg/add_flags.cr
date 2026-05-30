module FreeBSD::Pkg
  # Bitmask controlling `Database#add` (direct local archive install).
  #
  # Note: values are explicit because `PKG_ADD_AUTOMATIC` is bit 2 (value 4),
  # with bit 1 intentionally absent in the C header.
  # `@[Flags]` auto-assigns sequential powers of 2 which would be incorrect here.
  #
  # `None` (0) is generated automatically by `@[Flags]`.
  @[Flags]
  enum AddFlags : UInt32
    # Treat this install as an upgrade over an existing version (`PKG_ADD_UPGRADE`).
    Upgrade = 1
    # Mark the installed package as automatically installed (`PKG_ADD_AUTOMATIC`). Bit 2 — bit 1 is absent in the C header.
    Automatic = 4
    # Force installation even if the package is already installed (`PKG_ADD_FORCE`).
    Force = 8
    # Skip pre/post-install scripts (`PKG_ADD_NOSCRIPT`).
    NoScript = 16
    # Install even if the archive checksum does not match (`PKG_ADD_FORCE_MISSING`).
    ForceMissing = 32
    # Do not execute any system commands during installation (`PKG_ADD_NOEXEC`).
    NoExec = 128
    # Register the package in the database without extracting files (`PKG_ADD_REGISTER_ONLY`).
    RegisterOnly = 256
  end
end
