module FreeBSD::Pkg
  # Shared error-checking helpers for libpkg return codes.
  # Include this module in any class that calls libpkg functions.
  # Both instance methods and class methods gain access automatically.
  #
  # Symbol/array-of-symbols coercion for enum and `@[Flags]` enum
  # parameters lives on the enums themselves (`.from`, e.g.
  # `LoadFlags.from`, `MatchType.from`) rather than here — see
  # `FreeBSD::Casper::Service::Net::Mode.from` for the pattern this
  # mirrors.
  module PkgHelpers
    macro included
      extend PkgHelpers
    end

    # Raises `Error.from_pkg` unless *rc* is `EPKG_OK` (0).
    private def check_rc!(rc : Int32, fn : String) : Nil
      raise Error.from_pkg(rc, fn) unless rc == LibPkg::PkgErrorT::Ok.value
    end

    # Like `check_rc!` but also treats `EPKG_UP_TO_DATE` (9) as success.
    private def check_rc_or_uptodate!(rc : Int32, fn : String) : Nil
      return if rc == LibPkg::PkgErrorT::Ok.value || rc == LibPkg::PkgErrorT::UpToDate.value
      raise Error.from_pkg(rc, fn)
    end
  end
end
