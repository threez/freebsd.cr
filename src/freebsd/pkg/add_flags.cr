module FreeBSD::Pkg
  # Bitmask controlling `Database#add` (direct local archive install).
  #
  # Combine values with `|`, or pass a symbol / array of symbols:
  #
  # ```
  # db.add("/path/to/pkg.txz", flags: :force)
  # db.add("/path/to/pkg.txz", flags: [:force, :automatic])
  # db.add("/path/to/pkg.txz", flags: AddFlags::Force | AddFlags::Automatic)
  # ```
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

    # Coerce a `Symbol`, an `AddFlags`, or an `Enumerable` of either into a
    # single `AddFlags`. Symbols name members case-insensitively with `_`
    # word separators (`:force`, `:no_script`); an array is OR-folded so
    # `[:force, :automatic]` replaces `AddFlags::Force | AddFlags::Automatic`.
    # Raises `ArgumentError` naming a bad symbol.
    def self.from(value : Symbol | AddFlags) : AddFlags
      case value
      in AddFlags then value
      in Symbol   then parse(value.to_s)
      end
    end

    # :ditto:
    def self.from(values : Enumerable(Symbol | AddFlags)) : AddFlags
      values.reduce(AddFlags::None) { |acc, v| acc | from(v) }
    end
  end
end
