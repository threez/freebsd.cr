module FreeBSD::Pkg
  # Bitmask controlling job behaviour. Pass as the `flags:` argument to
  # `Jobs.install`, `Jobs.remove`, `Jobs.upgrade`, etc.
  #
  # Combine values with `|`, or pass a symbol / array of symbols:
  #
  # ```
  # Jobs.install(db, ["wget"], flags: :with_deps)
  # Jobs.install(db, ["wget"], flags: [:with_deps, :force])
  # Jobs.install(db, ["wget"], flags: JobFlags::WithDeps | JobFlags::Force)
  # ```
  #
  # `None` (0) is generated automatically by `@[Flags]`.
  @[Flags]
  enum JobFlags : UInt32
    # Simulate the operation without making any changes (`PKG_FLAG_DRY_RUN`).
    DryRun = 1
    # Reinstall or overwrite packages that are already installed (`PKG_FLAG_FORCE`).
    Force = 2
    # Also operate on dependent packages recursively (`PKG_FLAG_RECURSIVE`).
    Recursive = 4
    # Mark newly installed packages as automatically installed (`PKG_FLAG_AUTOMATIC`).
    Automatic = 8
    # Resolve and include dependencies automatically (`PKG_FLAG_WITH_DEPS`).
    WithDeps = 16
    # Skip pre/post-install scripts (`PKG_FLAG_NOSCRIPT`).
    NoScript = 32
    # Only upgrade packages that are already installed; skip new installs (`PKG_FLAG_UPGRADES_FOR_INSTALLED`).
    UpgradesOnly = 128
    # Download archives without installing them (`PKG_FLAG_SKIP_INSTALL`).
    SkipInstall = 256
    # Install packages even if their checksum does not match the repository (`PKG_FLAG_FORCE_MISSING`).
    ForceMissing = 512
    # Prefer IPv4 for network connections (`PKG_FLAG_USE_IPV4`).
    UseIpv4 = 2048
    # Prefer IPv6 for network connections (`PKG_FLAG_USE_IPV6`).
    UseIpv6 = 4096
    # Only upgrade packages with known vulnerabilities (`PKG_FLAG_UPGRADE_VULNERABLE`).
    UpgradeVulnerable = 8192
    # Do not execute any system commands during install/remove (`PKG_FLAG_NOEXEC`).
    NoExec = 16384
    # Keep fetched archive files after installation (`PKG_FLAG_KEEPFILES`).
    KeepFiles = 32768
    # Register the package in the database without extracting files (`PKG_FLAG_REGISTER_ONLY`).
    RegisterOnly = 65536
  end
end
